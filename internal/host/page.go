package host

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/denial"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/page"
	"golang.org/x/text/language"
	"kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

func (hh *HostHandler) pageHandlerFunc(
	ph page.PageHandler,
	translations *Translations,
	lang language.Tag,
) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log := logf.FromContext(r.Context())

		hh.mu.RLock()
		defer hh.mu.RUnlock()

		// lang is fixed at registration time by the literal path prefix
		// (or the default, for the bare route) -- there is no {l10n}
		// wildcard segment left to resolve per-request, so the class of
		// 400 that a malformed/unsupported l10n segment used to produce
		// here is gone structurally.
		l := lang

		if hh.IsAuthEnabled() && hh.authChecker != nil && ph.ParsedRequirements != nil {
			parsedUserEntitlements := hh.authChecker.GetParsedEntitlements(r.Context())
			authorized, err := hh.authChecker.VerifyResourceParsedEntitlements(
				"pages", ph.BasePath(), parsedUserEntitlements, *ph.ParsedRequirements)

			// A CHECK THAT FAILED TO RUN IS A SERVER FAULT, NOT A DENIAL.
			// The contract governs denials; a fault is neither a denial nor
			// an absence, so it is deliberately outside the three-row table
			// and gets no status from it -- no WWW-Authenticate, no
			// challenge, nothing that would tell the caller a credential
			// could fix this. It cannot: the checker never reached a verdict,
			// so nothing is known about the caller either way.
			//
			// Rendering it as a denial (which this gate did, and before that
			// as a 404 + r.URL.Path) misattributes an operator's outage to
			// the visitor and buries the fault at exactly the moment it needs
			// surfacing. The proxy gate answers 500 here too, so the two
			// gates still agree -- one condition, one vocabulary, with the
			// fault split out of it at BOTH sites rather than folded in at
			// both. docs/superpowers/specs/2026-08-28-denial-contract-design.md
			if err != nil {
				log.Error(err, "authorization check failed",
					"resource", "pages", "resourceName", ph.BasePath())
				http.Error(w, http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError)
				return
			}

			if !authorized {
				log.V(2).Info("unauthorized access attempt",
					"resource", "pages", "resourceName", ph.BasePath(), "l10n", l.String())

				// parsedUserEntitlements, not a second
				// GetParsedEntitlements: the gate above already derived it.
				outcome := denial.Classify(
					r.Context(), hh.authChecker, parsedUserEntitlements,
					"pages", ph.BasePath())

				// An anonymous caller gets the login page with a return trip
				// -- but only if it can render one. This branch used to
				// redirect every anonymous caller, so an API client asking
				// for a gated page received a 303 to an HTML form instead of
				// the 401 that would have told it what to do. See #184 for
				// why the branch sits here, ahead of discovery.
				_, hasLoginPage := hh.utilityPages[v1alpha1.LoginUtilityPageType]

				// ...and only for a caller who presented NO credential.
				// denial.Classify also calls a present-but-SUBJECT-LESS
				// context Unauthenticated, which is right for the STATUS --
				// a credential naming nobody cannot clear an identity gate
				// keyed on who the caller is -- but wrong for this redirect,
				// because the login form is where such a credential would
				// COME FROM: the caller would log in, SUCCEED, be returned
				// here, be classified Unauthenticated again and be sent back
				// to the form, forever, with nothing shown to say anything
				// failed.
				//
				// DEFENCE IN DEPTH, no longer load-bearing. This condition
				// was added when a subject-less credential could reach this
				// gate; it cannot any more. A subject-less credential is not
				// a supported configuration and is now refused at both ends
				// -- at mint (sign.Signer.Project / SignProjected,
				// apitoken.MintStatelessKey, and the login paths that call
				// them) and at validation (auth.Config.WithAuthentication
				// for a JWT, apitoken.TokenManager.ValidateToken for a
				// PASETO PAT) -- so no such caller arrives here carrying an
				// auth context at all.
				//
				// It stays because the cost is one map lookup and the
				// failure mode it bounds is an unbounded redirect loop with
				// no error surface: this gate should not depend on an
				// upstream invariant for a bound it can assert itself. The
				// distinction is also still the RIGHT one on its own terms
				// -- the discovery redirect's one-hop `denied=` marker
				// cannot bound this loop, because that guard works by having
				// the redirect TARGET carry it, whereas this loop passes
				// through LoginPost, which rebuilds the URL from `return=`
				// and drops everything else.
				//
				// Pinned by internal/host/subjectless_gate_test.go, which
				// injects the context directly and so tests this branch
				// rather than the upstream refusal.
				_, hasCredential := auth.GetAuthContext(r.Context())

				if outcome == denial.Unauthenticated && !hasCredential && hasLoginPage && acceptsHTML(r) {
					log.V(2).Info("unauthenticated, redirecting to login")
					// RequestURI, not Path: the return trip has to carry the
					// query string too, or a gated /search?q=foo sends the
					// user back to a bare /search. SafeReturnPath round-trips
					// a query and still collapses anything cross-origin.
					http.Redirect(w, r,
						"/-/login?return="+url.QueryEscape(r.URL.RequestURI()),
						http.StatusSeeOther)
					return
				}

				// FORBIDDEN has two browser renderings, selected by the
				// knob. Non-HTML callers fall through to the 403 below in
				// BOTH modes: the knob is about presentation, not about the
				// contract.
				//
				// The redirect is bounded to one hop. firstAuthorizedPage
				// can return a page that itself denies -- the navigation
				// walk and the page render are separate checks -- so a
				// request already carrying denied= renders the 403 instead
				// of redirecting again.
				if outcome != denial.Unauthenticated &&
					hh.pageDenialMode != PageDenialForbid &&
					acceptsHTML(r) &&
					!r.URL.Query().Has("denied") {

					first := hh.firstAuthorizedPage(r.Context(), &l, l.String() == hh.defaultLanguage)
					if first != "" {
						if l.String() != hh.defaultLanguage {
							first = "/" + l.String() + first
						}
						// r.URL.Path, not RequestURI: this is a label, never
						// a redirect target, so it needs no SafeReturnPath
						// collapse -- but it IS caller-influenceable, so any
						// consumer that renders it must treat it as text.
						target := first + "?denied=" + url.QueryEscape(r.URL.Path)
						log.V(2).Info("discovery redirect", "to", first, "denied", r.URL.Path)
						// A cached denial follows the user past the grant
						// change that fixed it.
						w.Header().Set("Cache-Control", "no-store")
						http.Redirect(w, r, target, http.StatusSeeOther)
						return
					}
					log.V(2).Info("no accessible page to discover; rendering 403")
				}

				denial.Write(w, r, denial.Opts{
					Outcome: outcome,
					// Locked: pageHandlerFunc holds hh.mu.RLock from the
					// top of the handler (see the defer above).
					Issuer: hh.issuerAddressLocked(),
				})
				return
			}
		}
		// Per-page seed: ph.Checksum() is sha256(ObservedGeneration +
		// sorted Status.Attributes), so the ETag invalidates only when
		// this specific KDexPage's observed state moved — not whenever
		// any other CR triggered a host reconcile. See #44.
		if hh.applyCachingHeadersWithSeed(w, r, hh.pageRequirements(&ph), hh.reconcileTime, l.String(), ph.Checksum()) {
			return
		}

		pageCache := hh.cacheManager.GetCache("page", cache.CacheOptions{})

		cacheKey := ph.CacheKey(l)

		rendered, ok, isCurrent, err := pageCache.Get(r.Context(), cacheKey)
		if err != nil {
			log.Error(err, "failed to get from cache", "page", ph.Name, "language", l)
		}

		if ok {
			// Check if we need to migrate this stale entry to the current generation
			if !isCurrent {
				log.V(2).Info("serving stale page, migrating in background", "page", ph.Name, "lang", l)

				// Background Migration. Hold hh.mu.RLock for the
				// duration of the re-render so the goroutine sees
				// consistent hh.* state vs concurrent SetHost writes.
				// See kdex-tech/host-manager#73.
				go func(p page.PageHandler, lang language.Tag, trans *Translations) {
					hh.mu.RLock()
					defer hh.mu.RUnlock()

					bgCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()

					newRender, err := hh.L10nRender(p, nil, lang, map[string]any{}, trans)
					if err == nil {
						_ = pageCache.Set(bgCtx, cacheKey, newRender)
					} else {
						log.Error(err, "background migration failed", "page", p.Name)
					}
				}(ph, l, translations)
			}

			log.V(2).Info("serving from cache", "page", ph.Name, "lang", l)

			// Serve the cached content (Current or Stale)
			hh.serveRendered(w, log, l, ph.Name, rendered)
			return
		}

		// 2. Cache Miss: Synchronous Render
		rendered, err = hh.L10nRender(ph, nil, l, map[string]any{}, translations)
		if err != nil {
			log.Error(err, "failed to render page", "page", ph.Name, "language", l)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Store the fresh render
		if err := pageCache.Set(r.Context(), cacheKey, rendered); err != nil {
			log.Error(err, "failed to set cache", "page", ph.Name, "language", l)
		}

		hh.serveRendered(w, log, l, ph.Name, rendered)
	}
}

// Small helper to keep the main handler clean
func (hh *HostHandler) serveRendered(w http.ResponseWriter, log logr.Logger, l language.Tag, name string, rendered string) {
	log.V(1).Info("serving", "page", name, "language", l)
	w.Header().Set("Content-Language", l.String())
	w.Header().Set("Content-Type", "text/html")
	if _, err := w.Write([]byte(rendered)); err != nil {
		log.Error(err, "failed to write response", "page", name, "language", l)
	}
}
