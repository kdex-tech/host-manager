package denial

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// fakeChecker reports a fixed answer for the identity probe. Classify calls
// VerifyResourceParsedEntitlements exactly once, with an EMPTY requirement set
// (the identity probe), so identityOK is the only knob a test needs.
type fakeChecker struct {
	identityOK bool
	err        error
	calls      int
	// recorded arguments from ParseRequirements and VerifyResourceParsedEntitlements
	parseReqsInput []kdexv1alpha1.SecurityRequirement
	verifyResource string
	verifyName     string
	verifyReqs     entitlements.ParsedRequirements
	verifyVerbs    []string
}

func (f *fakeChecker) GetParsedEntitlements(context.Context) entitlements.ParsedEntitlements {
	return entitlements.ParsedEntitlements{}
}

func (f *fakeChecker) ParseRequirements(reqs []kdexv1alpha1.SecurityRequirement) entitlements.ParsedRequirements {
	f.parseReqsInput = reqs
	return entitlements.ParsedRequirements{}
}

func (f *fakeChecker) VerifyResourceParsedEntitlements(
	resource string, name string,
	_ entitlements.ParsedEntitlements, reqs entitlements.ParsedRequirements,
	verbs ...string,
) (bool, error) {
	f.calls++
	f.verifyResource = resource
	f.verifyName = name
	f.verifyReqs = reqs
	f.verifyVerbs = verbs
	return f.identityOK, f.err
}

func authedCtx() context.Context {
	return auth.SetAuthContext(context.Background(), auth.AuthContext{"sub": "alice"})
}

func TestClassifyAnonymousIsUnauthenticated(t *testing.T) {
	c := &fakeChecker{identityOK: true}
	if got := Classify(context.Background(), c, "functions", "/api/v1/x"); got != Unauthenticated {
		t.Fatalf("Classify = %v, want Unauthenticated", got)
	}
	if c.calls != 0 {
		t.Fatalf("identity probe ran %d times for an anonymous caller, want 0", c.calls)
	}
}

func TestClassifyAuthenticatedWithoutIdentityIsNoIdentity(t *testing.T) {
	c := &fakeChecker{identityOK: false}
	if got := Classify(authedCtx(), c, "functions", "/api/v1/x"); got != NoIdentity {
		t.Fatalf("Classify = %v, want NoIdentity", got)
	}
}

func TestClassifyAuthenticatedWithIdentityIsInsufficientScope(t *testing.T) {
	c := &fakeChecker{identityOK: true}
	if got := Classify(authedCtx(), c, "functions", "/api/v1/x"); got != InsufficientScope {
		t.Fatalf("Classify = %v, want InsufficientScope", got)
	}
}

func TestClassifyNilCheckerIsNoIdentity(t *testing.T) {
	if got := Classify(authedCtx(), nil, "functions", "/api/v1/x"); got != NoIdentity {
		t.Fatalf("Classify = %v, want NoIdentity", got)
	}
}

func TestClassifyIdentityProbeUsesEmptyRequirementSet(t *testing.T) {
	// The identity probe must pass nil/empty requirements so that
	// VerifyResourceParsedEntitlements reduces to exactly the identity gate.
	c := &fakeChecker{identityOK: true}
	if got := Classify(authedCtx(), c, "functions", "/api/v1/x", "read", "write"); got != InsufficientScope {
		t.Fatalf("Classify = %v, want InsufficientScope", got)
	}
	// ParseRequirements must be called with nil (not a non-nil empty slice)
	if c.parseReqsInput != nil {
		t.Fatalf("ParseRequirements called with %v, want nil", c.parseReqsInput)
	}
	// VerifyResourceParsedEntitlements must be called with correct resource and name
	if c.verifyResource != "functions" {
		t.Fatalf("VerifyResourceParsedEntitlements resource = %q, want \"functions\"", c.verifyResource)
	}
	if c.verifyName != "/api/v1/x" {
		t.Fatalf("VerifyResourceParsedEntitlements name = %q, want \"/api/v1/x\"", c.verifyName)
	}
}

func TestWriteUnauthenticatedNonOAuth2UsesRealm(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil), Opts{
		Outcome: Unauthenticated,
		Issuer:  "https://example.test",
	})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	want := `Bearer realm="https://example.test"`
	if got := rr.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}

func TestWriteUnauthenticatedOAuth2UsesResourceMetadataAndNoErrorParam(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/mcp", nil), Opts{
		Outcome:          Unauthenticated,
		Issuer:           "https://example.test",
		ResourceMetadata: "https://example.test/.well-known/oauth-protected-resource/api/v1/mcp",
	})
	got := rr.Header().Get("WWW-Authenticate")
	want := `Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource/api/v1/mcp"`
	if got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
	// RFC 6750 3.1: the error parameter is omitted when no credentials were sent.
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
}

func TestWriteNoIdentityIs403WithoutChallenge(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil), Opts{
		Outcome:          NoIdentity,
		Issuer:           "https://example.test",
		ResourceMetadata: "https://example.test/.well-known/oauth-protected-resource/api/v1/x",
		Scopes:           []string{"users:*:admin"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("challenge = %q, want none: naming a scope implies a scope would fix it", got)
	}
}

func TestWriteInsufficientScopeIs403WithScope(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/mcp", nil), Opts{
		Outcome:          InsufficientScope,
		Issuer:           "https://example.test",
		ResourceMetadata: "https://example.test/.well-known/oauth-protected-resource/api/v1/mcp",
		Scopes:           []string{"users:*:admin", "vector_stores:*:read"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	want := `Bearer error="insufficient_scope", scope="users:*:admin vector_stores:*:read", ` +
		`resource_metadata="https://example.test/.well-known/oauth-protected-resource/api/v1/mcp"`
	if got := rr.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}

func TestWriteInsufficientScopeNonOAuth2HasNoChallenge(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/x", nil), Opts{
		Outcome: InsufficientScope,
		Issuer:  "https://example.test",
		Scopes:  []string{"users:*:admin"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Fatalf("challenge = %q, want none for a non-oauth2 resource", got)
	}
}

func TestWriteUnauthenticatedWithNoIssuerUsesBareBearer(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/gated", nil), Opts{Outcome: Unauthenticated})
	if got := rr.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Fatalf(`challenge = %q, want a bare "Bearer": realm="" is worse than none`, got)
	}
}

func TestChallengeDropsUnsafeScopeValues(t *testing.T) {
	rr := httptest.NewRecorder()
	Write(rr, httptest.NewRequest(http.MethodGet, "/api/v1/mcp", nil), Opts{
		Outcome:          InsufficientScope,
		ResourceMetadata: "https://example.test/.well-known/oauth-protected-resource/api/v1/mcp",
		Scopes: []string{
			`bad"quote`,    // quote
			"good:scope",   // kept (no unsafe chars)
			`back\slash`,   // backslash
			"has space",    // space
			"has,comma",    // comma (auth-param delimiter)
			"has\ttab",     // tab
			"has\nnewline", // newline
		},
	})
	want := `Bearer error="insufficient_scope", scope="good:scope", ` +
		`resource_metadata="https://example.test/.well-known/oauth-protected-resource/api/v1/mcp"`
	if got := rr.Header().Get("WWW-Authenticate"); got != want {
		t.Fatalf("challenge = %q, want %q", got, want)
	}
}
