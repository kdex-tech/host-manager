package host

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/kdex-tech/host-manager/internal/page"
	"github.com/kdex-tech/host-manager/internal/rewrite"
	"golang.org/x/text/language"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// rewriteTarget is a rewrite page's target as resolved for one mux snapshot
// (#217). basePath is the target's declared basePath; exact is the path its
// base route answers at, used when rewrite.path is empty. Since #220 that is
// the basePath itself for every target kind: an HTML or text page registers
// at its exact basePath, and a slash-terminated basePath (/, /docs/) at that
// same string via {$}. localized is true only for a KDexPage target that
// registers per-language routes; legacySlash is true only for a KDexPage
// target that also registers its legacy slash form (exact+"/") as a 301 to
// exact, a route a rewrite must never dispatch into.
type rewriteTarget struct {
	basePath    string
	exact       string
	localized   bool
	legacySlash bool
}

// rewriteMarkerKey marks a request already re-dispatched by a rewrite, so a
// second rewrite hop answers 508 instead of looping. The page controller
// forbids that topology; this guards the window before it re-reconciles.
type rewriteMarkerKey struct{}

// resolveRewriteTarget finds ref among this snapshot's pages and functions.
// A rewrite-mode page, a missing page, and a function that is not Ready or is
// internal are all "not found": their routes are not servable as a target.
func resolveRewriteTarget(
	ref kdexv1alpha1.KDexObjectReference,
	pagesByName map[string]page.PageHandler,
	functions []kdexv1alpha1.KDexFunction,
) (rewriteTarget, bool) {
	switch ref.Kind {
	case "KDexPage":
		ph, ok := pagesByName[ref.Name]
		if !ok || ph.Page == nil || ph.Page.Rewrite != nil {
			return rewriteTarget{}, false
		}
		bp := ph.Page.BasePath
		return rewriteTarget{
			basePath:    bp,
			exact:       bp,
			localized:   isLocalized(ph.Page.Localized),
			legacySlash: hasLegacySlashRoute(bp, ph.Page),
		}, true
	case "KDexFunction":
		for _, f := range functions {
			if f.Name == ref.Name && !f.Spec.Internal && f.Status.State == kdexv1alpha1.KDexFunctionStateReady {
				return rewriteTarget{basePath: f.Spec.API.BasePath, exact: f.Spec.API.BasePath}, true
			}
		}
	}
	return rewriteTarget{}, false
}

// rewriteHandlerFunc serves a rewrite page registered for lang: it runs the
// alias page's own gate, builds the target path, and re-dispatches a clone of
// the request into mux -- the snapshot this handler was registered into, never
// hh.Mux, which a reconcile may have swapped since.
//
// LOCKING: the gate and the canonical base read hh state under hh.mu.RLock,
// and the lock is released BEFORE dispatch (via a deferred unlock in a
// closure, so a panic inside the gate cannot leave hh.mu read-locked and wedge
// every later writer; #26/#51). The target's pageHandlerFunc takes
// hh.mu.RLock itself; holding it across the dispatch would read-lock twice on
// one goroutine, which deadlocks as soon as a SetHost writer queues between
// the two acquisitions.
func (hh *HostHandler) rewriteHandlerFunc(pr pageRender, lang language.Tag, mux *http.ServeMux) http.HandlerFunc {
	ph := pr.ph
	rw := ph.Page.Rewrite
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(rewriteMarkerKey{}) != nil {
			http.Error(w, http.StatusText(http.StatusLoopDetected), http.StatusLoopDetected)
			return
		}
		if !pr.rewriteFound {
			hh.log.V(1).Info("rewrite target not resolvable; serving 404", "page", ph.Name, "targetKind", rw.TargetRef.Kind, "targetName", rw.TargetRef.Name)
			hh.serveError(w, r, http.StatusNotFound, "not found")
			return
		}

		allowed, base, defaultLang := func() (bool, string, string) {
			hh.mu.RLock()
			defer hh.mu.RUnlock()
			return hh.pageGateLocked(w, r, ph, lang), hh.issuerAddressLocked(), hh.defaultLanguage
		}()
		if !allowed {
			return
		}

		target, err := rewrite.Target(pr.rewrite.basePath, pr.rewrite.exact, rw.Path, ph.Page.PatternPath, r.PathValue)
		switch {
		case errors.Is(err, rewrite.ErrNotFound):
			hh.serveError(w, r, http.StatusNotFound, "not found")
			return
		case errors.Is(err, rewrite.ErrUnsafe):
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		case err != nil:
			hh.log.Error(err, "rewrite target build failed", "page", ph.Name)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		exact := pr.rewrite.exact
		if pr.rewrite.localized && lang.String() != defaultLang {
			target = "/" + lang.String() + target
			exact = "/" + lang.String() + exact
		}
		// Never dispatch into the target's legacy slash redirect (#220): an
		// empty trailing value builds exact+"/", whose 301 would send the
		// client to the TARGET URL. The exact route serves the same page.
		if pr.rewrite.legacySlash && target == exact+"/" {
			target = exact
		}

		r2 := r.Clone(context.WithValue(r.Context(), rewriteMarkerKey{}, true))
		r2.URL.Path = target
		r2.URL.RawPath = ""

		// A slashless target the mux would answer with its own trailing-slash
		// redirect (an authored pattern like /profile/{user}/) is followed
		// here, internally: the client never sees a redirect, so it neither
		// learns the target URL nor gets bounced back to an alias URL it
		// already requested.
		if slashRedirect(mux, r2) {
			target += "/"
			r2.URL.Path = target
		}

		// System routes (/-/, /.well-known/, favicon) are never rewrite
		// targets: a multi-segment value could otherwise alias a KDexPage
		// onto the host's own auth and discovery endpoints. Checked on the
		// final dispatch path.
		if isSystemPath(target) {
			hh.serveError(w, r, http.StatusNotFound, "not found")
			return
		}

		if rw.Canonical && base != "" {
			// EscapedPath, not the raw target: a request value holding '>'
			// or '"' would otherwise close the URI and inject a second link.
			w.Header().Set("Link", "<"+base+(&url.URL{Path: target}).EscapedPath()+`>; rel="canonical"`)
		}

		mux.ServeHTTP(w, r2)
	}
}

// redirectHandlerType is the concrete type http.RedirectHandler returns, the
// type ServeMux.Handler uses for its own trailing-slash redirect. Taken from
// the exported constructor rather than named, so it tracks the stdlib.
var redirectHandlerType = reflect.TypeOf(http.RedirectHandler("/", http.StatusTemporaryRedirect))

// slashRedirect reports whether mux would answer r with ServeMux's own
// trailing-slash redirect (to r.URL.Path+"/").
//
// ServeMux.Handler exposes that decision only as its returned handler: for a
// slash redirect it is a RedirectHandler and the pattern is the one matching
// the slash form, which is indistinguishable by pattern alone from a subtree
// pattern serving r directly. So the handler's type is compared against
// RedirectHandler's. ServeMux's only other RedirectHandler, the path-cleaning
// one, cannot fire here: rewrite.Target refuses any '//' or '.'/'..' segment
// (and an empty path yields the CRD-validated basePath), so the target is
// already clean. No page or function route is registered as a
// RedirectHandler (legacy and language redirects are HandlerFuncs).
func slashRedirect(mux *http.ServeMux, r *http.Request) bool {
	if strings.HasSuffix(r.URL.Path, "/") {
		return false
	}
	h, _ := mux.Handler(r)
	return reflect.TypeOf(h) == redirectHandlerType
}
