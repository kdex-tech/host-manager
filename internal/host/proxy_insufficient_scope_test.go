package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// insufficientScopeFixture builds an oauth2-protected function whose operation
// requires `requiredScope`, gated by the REAL auth.AuthorizationChecker.
//
// The stub checkers used elsewhere (entitlementGateChecker) collapse the
// identity gate and the operation requirement into one bool, so they cannot
// produce the InsufficientScope row at all. Only the real checker splits them:
// identity is `functions:<basePath>:read` in the default ("bearer") bucket,
// while the declared requirement lives in the "oauth2" bucket, which nothing
// but the PAT bridge ever populates.
func insufficientScopeFixture(t *testing.T, domain, basePath, requiredScope string) http.Handler {
	t.Helper()
	logf.SetLogger(logr.Discard())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	fn := newReadyFunctionWithOAuth2(t, basePath, []string{requiredScope})
	fn.Status.URL = upstream.URL

	cacheManager, _ := cache.NewCacheManager("", "insufficient-scope-test", nil)

	hh := &HostHandler{
		log:          logr.Discard(),
		scheme:       "https",
		cacheManager: cacheManager,
		authChecker:  auth.NewAuthorizationChecker(nil, logr.Discard()),
		host: &kdexv1alpha1.KDexHostSpec{
			Routing: kdexv1alpha1.Routing{Domains: []string{domain}},
		},
		functions:  []kdexv1alpha1.KDexFunction{fn},
		authConfig: challengeFixtureAuthConfig(t),
	}

	return hh.reverseProxyHandler(&fn, "https://"+domain)
}

// TestInsufficientScopeChallengeAtTheProxyGate is the gate-level guard for the
// headline mitigation. The design doc names this challenge as what keeps the
// branch's one observable regression -- "an authenticated MCP client with
// insufficient scope now sees 403, not 401" -- from costing that client its
// step-up path. Before this test, the only assertions on it lived in
// internal/auth/denial/denial_test.go, where Opts is hand-built: assigning nil
// to fh.oauth2Scopes at internal/host/proxy.go:399 passed the whole suite.
//
// The caller here CLEARS the identity gate (it holds
// `functions:/api/v1/mcp:read` in the default bucket) and FAILS the operation
// requirement (`mcp:tools:call`, declared under oauth2, which its bucketing
// cannot satisfy). That is exactly the InsufficientScope row.
func TestInsufficientScopeChallengeAtTheProxyGate(t *testing.T) {
	const (
		domain        = "dev.knowdrive.ai"
		basePath      = "/api/v1/mcp"
		requiredScope = "mcp:tools:call"
	)

	h := insufficientScopeFixture(t, domain, basePath, requiredScope)

	req := httptest.NewRequest(http.MethodPost, basePath, strings.NewReader("{}"))
	req.Host = domain
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		"sub": "mcp-bob",
		// Clears the identity gate, satisfies nothing the operation declares.
		"entitlements": []string{"functions:" + basePath + ":read"},
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a credential that clears identity but fails the requirement", rr.Code)
	}

	got := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(got, `error="insufficient_scope"`) {
		t.Fatalf("challenge = %q, want error=\"insufficient_scope\" (RFC 6750 3.1)", got)
	}
	if !strings.Contains(got, `scope="`+requiredScope+`"`) {
		t.Fatalf("challenge = %q, want scope=%q naming the required scope; "+
			"without it the client has a status but no step-up path", got, requiredScope)
	}
	if !strings.Contains(got, `resource_metadata="https://`+domain+`/.well-known/oauth-protected-resource`+basePath+`"`) {
		t.Fatalf("challenge = %q, want the RFC 9728 resource_metadata pointer", got)
	}
}

// TestNoIdentityChallengeAtTheProxyGate is the gate-level guard for #194: an
// authenticated caller who FAILS the identity gate on an oauth2-protected
// resource must still receive the RFC 9728 step-up challenge, not the bare 403
// v0.8.0 regressed to. Like TestInsufficientScopeChallengeAtTheProxyGate, it
// proves the CALL SITE populates Opts.ResourceMetadata/Scopes on the NoIdentity
// path -- a hand-built Opts unit test in internal/auth/denial cannot catch a
// call site that passes neither, which is exactly how #194 shipped.
//
// The operation scope here IS the identity gate (functions:<basePath>:read --
// the authoring convention). That collapses InsufficientScope into
// unreachability, so every scoped denial arrives as NoIdentity and this branch
// is the only one that can carry the client's step-up.
func TestNoIdentityChallengeAtTheProxyGate(t *testing.T) {
	const (
		domain   = "dev.knowdrive.ai"
		basePath = "/api/v1/mcp"
		gate     = "functions:/api/v1/mcp:read"
	)

	h := insufficientScopeFixture(t, domain, basePath, gate)

	req := httptest.NewRequest(http.MethodPost, basePath, strings.NewReader("{}"))
	req.Host = domain
	req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{
		// A real subject, but holding nothing -- fails the identity gate.
		"sub": "mcp-carol",
	}))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a credential that fails the identity gate", rr.Code)
	}

	got := rr.Header().Get("WWW-Authenticate")
	if !strings.Contains(got, `error="insufficient_scope"`) {
		t.Fatalf("challenge = %q, want error=\"insufficient_scope\": #194 restores the step-up path an "+
			"under-scoped oauth2 caller lost", got)
	}
	if !strings.Contains(got, `scope="`+gate+`"`) {
		t.Fatalf("challenge = %q, want scope=%q naming the gate scope the AS can grant", got, gate)
	}
	if !strings.Contains(got, `resource_metadata="https://`+domain+`/.well-known/oauth-protected-resource`+basePath+`"`) {
		t.Fatalf("challenge = %q, want the RFC 9728 resource_metadata pointer", got)
	}
}
