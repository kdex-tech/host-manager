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
// routes are registered at, used when rewrite.path is empty so the mux never
// slash-redirects to the target; localized is true only for a KDexPage target
// that registers per-language routes.
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
		exact := bp
		if ph.Page.MimeType == "" && !strings.HasSuffix(bp, "/") {
			exact = bp + "/"
		}
		return rewriteTarget{basePath: bp, exact: exact, localized: isLocalized(ph.Page.Localized)}, true
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
		// System routes (/-/, /.well-known/, favicon) are never rewrite
		// targets: a multi-segment value could otherwise alias a KDexPage
		// onto the host's own auth and discovery endpoints.
		if isSystemPath(target) {
			hh.serveError(w, r, http.StatusNotFound, "not found")
			return
		}

		r2 := r.Clone(context.WithValue(r.Context(), rewriteMarkerKey{}, true))
		r2.URL.Path = target
		r2.URL.RawPath = ""

		// A slashless target the mux would answer with a trailing-slash
		// redirect must not send the browser to the TARGET URL: send it to
		// the alias's own slash form instead, which dispatches here again.
		if code, ok := slashRedirect(mux, r2); ok {
			http.Redirect(w, r, aliasSlashURL(r.URL), code)
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

// slashRedirect reports whether mux would answer r with a trailing-slash
// redirect (to r.URL.Path+"/"), and with which status code.
//
// ServeMux.Handler exposes that decision only as its returned handler: for a
// slash redirect it is a RedirectHandler and the pattern is the one matching
// the slash form, which is indistinguishable by pattern alone from a subtree
// pattern serving r directly. So the handler's type is compared against
// RedirectHandler's, and the redirect handler (side-effect free: it only
// writes a Location header and a short body) is run into a header-only
// recorder to read the code and Location it would send. Only a Location of
// exactly r.URL.Path+"/" counts: any other redirect is left to the mux.
func slashRedirect(mux *http.ServeMux, r *http.Request) (int, bool) {
	if strings.HasSuffix(r.URL.Path, "/") {
		return 0, false
	}
	h, _ := mux.Handler(r)
	if reflect.TypeOf(h) != redirectHandlerType {
		return 0, false
	}
	rec := &headerRecorder{header: http.Header{}}
	h.ServeHTTP(rec, r)
	loc, err := url.Parse(rec.header.Get("Location"))
	if err != nil || loc.Path != r.URL.Path+"/" {
		return 0, false
	}
	return rec.code, true
}

// aliasSlashURL is the request's own path with a trailing slash, query
// kept, escaped as the client sent it.
func aliasSlashURL(u *url.URL) string {
	s := u.EscapedPath() + "/"
	if u.RawQuery != "" {
		s += "?" + u.RawQuery
	}
	return s
}

// headerRecorder captures a handler's status and headers and discards its
// body. It is only ever handed a RedirectHandler.
type headerRecorder struct {
	header http.Header
	code   int
}

func (h *headerRecorder) Header() http.Header         { return h.header }
func (h *headerRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (h *headerRecorder) WriteHeader(code int)        { h.code = code }
