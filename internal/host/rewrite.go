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
// registers per-language routes.
type rewriteTarget struct {
	basePath  string
	exact     string
	localized bool
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
		return rewriteTarget{basePath: bp, exact: bp, localized: isLocalized(ph.Page.Localized)}, true
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
		if pr.rewrite.localized && lang.String() != defaultLang {
			target = "/" + lang.String() + target
		}

		r2 := r.Clone(context.WithValue(r.Context(), rewriteMarkerKey{}, true))
		r2.URL.Path = target
		r2.URL.RawPath = ""

		// Redirect routes the target path lands on are followed here,
		// internally: the client never sees their Location, so it neither
		// learns the target URL nor gets bounced back to an alias URL it
		// already requested.
		target, ok := followInternalRedirects(mux, r2)
		if !ok {
			hh.log.Error(nil, "rewrite target does not settle on a non-redirect route; serving 508", "page", ph.Name, "path", r.URL.Path)
			http.Error(w, http.StatusText(http.StatusLoopDetected), http.StatusLoopDetected)
			return
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

// maxRewriteRedirectHops bounds followInternalRedirects. The longest chain
// page registration produces is two hops (e.g. /en/profile/bob: ServeMux's
// slash redirect to /en/profile/bob/, then the default-language 301 to
// /profile/bob/); three leaves one hop of slack.
const maxRewriteRedirectHops = 3

// followInternalRedirects resolves r's path through every redirect route the
// mux would answer it with, rewriting r.URL.Path in place, and returns the
// final path. It follows, up to maxRewriteRedirectHops times:
//   - an internalRedirect page route (the #220 legacy slash 301 of ANY page,
//     the default-language 301): to its redirectPath;
//   - ServeMux's own trailing-slash redirect (an authored slash-terminated
//     pattern such as /profile/{user}/): to path+"/".
//
// It reports false when the path still redirects after the last hop (a
// cycle, or a chain no registration produces), which the caller answers with
// 508: like the second-rewrite-hop guard, it is a server-side loop, and a 404
// would hide it. It also reports false, failing closed, for any other
// ServeMux redirect, which would otherwise reach the client.
//
// ServeMux.Handler exposes its slash redirect only as its returned handler: a
// RedirectHandler, whose pattern is the one matching the slash form. So the
// handler's type is compared against RedirectHandler's. ServeMux's only other
// RedirectHandler, the path-cleaning one, cannot fire here: rewrite.Target
// refuses any '//' or '.'/'..' segment (and an empty path yields the
// CRD-validated basePath), and redirectPath values are registered paths, so
// the path is always clean. No route is registered as a RedirectHandler.
func followInternalRedirects(mux *http.ServeMux, r *http.Request) (string, bool) {
	for hop := 0; ; hop++ {
		h, _ := mux.Handler(r)
		var next string
		if ir, ok := h.(internalRedirect); ok {
			next = ir.redirectPath(r)
		} else if reflect.TypeOf(h) != redirectHandlerType {
			return r.URL.Path, true
		} else if strings.HasSuffix(r.URL.Path, "/") {
			// Not a slash redirect (see above: cannot happen). Fail closed
			// rather than hand the client a mux-built Location.
			return "", false
		} else {
			next = r.URL.Path + "/"
		}
		if hop == maxRewriteRedirectHops {
			return "", false
		}
		r.URL.Path = next
	}
}
