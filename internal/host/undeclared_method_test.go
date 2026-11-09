package host

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// withHeld attaches an AUTHENTICATED caller holding `held` to the request.
// requestAs does the same inline, but these tests need the response headers,
// not just the status code.
func withHeld(req *http.Request, held []string) *http.Request {
	ac := auth.AuthContext{"sub": "tester", "entitlements": held}
	return req.WithContext(auth.SetAuthContext(req.Context(), ac))
}

// A function that declares exactly ONE operation: GET, gated on an entitlement.
// Every other method on this path is undeclared, which is the point.
func getOnlyFn() *kdexv1alpha1.KDexFunction {
	return &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-readonly", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: "/api/v1/notes",
				Paths: map[string]kdexv1alpha1.PathItem{
					"/api/v1/notes": {
						Get: &runtime.RawExtension{Raw: []byte(`{
							"operationId": "listNotes",
							"security": [{"bearer": ["functions:/api/v1/notes:read"]}]
						}`)},
					},
				},
			},
		},
	}
}

// A function declaring GET and DELETE, to assert the Allow header lists every
// declared method rather than only the one that happened to be looked up.
func getDeleteFn() *kdexv1alpha1.KDexFunction {
	fn := getOnlyFn()
	item := fn.Spec.API.Paths["/api/v1/notes"]
	item.Delete = &runtime.RawExtension{Raw: []byte(`{
		"operationId": "deleteNotes",
		"security": [{"bearer": ["functions:/api/v1/notes:write"]}]
	}`)}
	fn.Spec.API.Paths["/api/v1/notes"] = item
	return fn
}

// The gate works on the route the function DID declare. This is the control: if
// it ever fails, the assertions below prove nothing about fail-closed behaviour.
func TestGate_DeclaredRouteIsStillEnforced(t *testing.T) {
	h, reached := binderFixture(t, getOnlyFn())

	code := requestAs(t, h, "GET", "/api/v1/notes", []string{"functions:/api/v1/notes:read"}, nil)
	assert.Equal(t, http.StatusOK, code, "a holder of the declared entitlement must pass")
	assert.True(t, *reached, "the upstream must be reached on an authorized GET")

	h2, reached2 := binderFixture(t, getOnlyFn())
	code = requestAs(t, h2, "GET", "/api/v1/notes", nil, nil)
	assert.NotEqual(t, http.StatusOK, code, "a caller holding nothing must be denied")
	assert.False(t, *reached2, "a denied GET must not reach the upstream")
}

// THE HOLE. An undeclared method on a declared path used to fall through to
// EMPTY requirements -- "allows access if identity matches" -- so any
// authenticated caller could POST, PUT, PATCH or DELETE a read-only route and
// be proxied straight to the backend with none of the route's entitlements
// checked. The function never declared the method, so there is no authorization
// to apply and nothing to fall back to: the only safe answer is to refuse.
func TestGate_UndeclaredMethodIsRefused(t *testing.T) {
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE"} {
		t.Run(method, func(t *testing.T) {
			h, reached := binderFixture(t, getOnlyFn())

			// The caller is authenticated and even holds the route's own read
			// entitlement -- everything short of a declaration for this method.
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/api/v1/notes", nil)
			req = withHeld(req, []string{"functions:/api/v1/notes:read"})
			h.ServeHTTP(rr, req)

			assert.Equal(t, http.StatusMethodNotAllowed, rr.Code,
				"an undeclared %s must be refused, not admitted on identity alone", method)
			assert.False(t, *reached,
				"an undeclared %s must never reach the backend", method)
			assert.Equal(t, "GET, HEAD", rr.Header().Get("Allow"),
				"a 405 must tell the caller what the route does declare")
		})
	}
}

// The Allow header is built from the declaration, not from whatever was looked
// up, and HEAD rides along with GET (RFC 9110: a resource supporting GET
// supports HEAD).
func TestGate_AllowListsEveryDeclaredMethod(t *testing.T) {
	h, _ := binderFixture(t, getDeleteFn())

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/notes", nil)
	req = withHeld(req, nil)
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code)
	got := strings.Split(rr.Header().Get("Allow"), ", ")
	sort.Strings(got)
	assert.Equal(t, []string{"DELETE", "GET", "HEAD"}, got)
}

// A GET whose declared requirements go BEYOND the function-level entitlement.
// This is what makes the HEAD test below discriminating: the fall-through still
// required `functions:<basePath>:<op>`, so on a route whose only requirement IS
// that entitlement, inheriting GET's requirements and falling through are
// indistinguishable. The extra `notes:private:read` is the difference.
func getOnlyScopedFn() *kdexv1alpha1.KDexFunction {
	fn := getOnlyFn()
	item := fn.Spec.API.Paths["/api/v1/notes"]
	item.Get = &runtime.RawExtension{Raw: []byte(`{
		"operationId": "listNotes",
		"security": [{"bearer": [
			"functions:/api/v1/notes:read",
			"notes:private:read"
		]}]
	}`)}
	fn.Spec.API.Paths["/api/v1/notes"] = item
	return fn
}

// HEAD is not refused on a GET-only route -- but it is not free either. It is
// verified against the GET operation's OWN requirements, so a caller who could
// not GET the route cannot HEAD it to read its headers. Before the fix, HEAD
// took the empty-requirements path, which still demanded the function-level
// entitlement but skipped everything the operation actually declared.
func TestGate_HeadIsVerifiedAgainstTheGetRequirements(t *testing.T) {
	const fnGrant = "functions:/api/v1/notes:read"
	const scopeGrant = "notes:private:read"

	// The discriminating case: this caller satisfies the function-level
	// entitlement -- enough for the old fall-through -- but not the GET
	// operation's second requirement.
	h, reached := binderFixture(t, getOnlyScopedFn())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("HEAD", "/api/v1/notes", nil)
	req = withHeld(req, []string{fnGrant})
	h.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusOK, rr.Code,
		"HEAD must be held to the GET operation's requirements, not the function-level grant")
	assert.NotEqual(t, http.StatusMethodNotAllowed, rr.Code, "HEAD on a GET route is not a 405")
	assert.False(t, *reached, "a denied HEAD must not reach the upstream")

	// Positive control: a caller who could GET the route can HEAD it.
	h2, reached2 := binderFixture(t, getOnlyScopedFn())
	code := requestAs(t, h2, "HEAD", "/api/v1/notes", []string{fnGrant, scopeGrant}, nil)
	assert.Equal(t, http.StatusOK, code, "HEAD with the GET requirements held must pass")
	assert.True(t, *reached2, "an authorized HEAD must reach the upstream")
}

// An undeclared OPTIONS is answered, not proxied: Allow is what OPTIONS asks
// for. The backend never sees it, so a backend answering its own preflight has
// to declare the operation -- the one behaviour this change takes away.
func TestGate_UndeclaredOptionsIsAnsweredLocally(t *testing.T) {
	h, reached := binderFixture(t, getDeleteFn())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/api/v1/notes", nil)
	req = withHeld(req, nil)
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusNoContent, rr.Code)
	got := strings.Split(rr.Header().Get("Allow"), ", ")
	sort.Strings(got)
	assert.Equal(t, []string{"DELETE", "GET", "HEAD"}, got)
	assert.False(t, *reached, "an undeclared OPTIONS must not reach the backend")
}

// A declared method is unaffected by any of the above: a function that really
// does declare POST still has its POST gated and proxied.
func TestGate_DeclaredWriteMethodStillWorks(t *testing.T) {
	fn := getOnlyFn()
	item := fn.Spec.API.Paths["/api/v1/notes"]
	item.Post = &runtime.RawExtension{Raw: []byte(`{
		"operationId": "createNote",
		"security": [{"bearer": ["functions:/api/v1/notes:write"]}]
	}`)}
	fn.Spec.API.Paths["/api/v1/notes"] = item

	// Reaching a function at all needs a read on the function resource, on top
	// of whatever the operation declares -- which is exactly why a lone read
	// grant used to be enough to be proxied an undeclared POST.
	h, reached := binderFixture(t, fn)
	held := []string{"functions:/api/v1/notes:read", "functions:/api/v1/notes:write"}
	code := requestAs(t, h, "POST", "/api/v1/notes", held, nil)
	assert.Equal(t, http.StatusOK, code, "a declared POST must still be served")
	assert.True(t, *reached)

	h2, reached2 := binderFixture(t, fn)
	code = requestAs(t, h2, "POST", "/api/v1/notes", []string{"functions:/api/v1/notes:read"}, nil)
	assert.NotEqual(t, http.StatusMethodNotAllowed, code,
		"a declared POST held without its entitlement is a denial, not a 405")
	assert.False(t, *reached2)
}

// A path the function never declared keeps today's behaviour. This is NOT a
// claim that it is correct -- it is the deliberate boundary of this change: the
// undeclared-PATH fall-through is filed separately, because unlike a method a
// subtree pass-through may be load-bearing for an existing function. The
// assertion is here so that closing the path hole is a visible, intentional
// change to this test rather than a silent one.
func TestGate_UndeclaredPathIsNotYetRefused(t *testing.T) {
	h, _ := binderFixture(t, getOnlyFn())
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/notes/deeper/unknown", nil)
	req = withHeld(req, nil)
	h.ServeHTTP(rr, req)

	assert.NotEqual(t, http.StatusMethodNotAllowed, rr.Code,
		"the 405 must key on a DECLARED path, so an unmatched path is untouched by it")
}

// The ORDER is deliberate, not incidental: the refusal is decided before the
// authorization gate, so an undeclared method answers 405 even to a caller who
// presented no credential at all -- not a 401 challenge. Re-authorizing cannot
// make an undeclared route exist, so a challenge would send an MCP client round
// a loop it can never win. Nothing is leaked by saying so: /-/openapi already
// publishes every Ready function's paths AND methods to anonymous callers
// (TestOpenAPIPublishesGatedFunctionPathsToAnonymousCallers). If that ever
// becomes gated or caller-filtered, revisit this test and the branch it pins.
func TestGate_UndeclaredMethodBeatsThe401Challenge(t *testing.T) {
	h, reached := binderFixture(t, getOnlyFn())
	rr := httptest.NewRecorder()
	// No auth context at all: an anonymous caller.
	h.ServeHTTP(rr, httptest.NewRequest("DELETE", "/api/v1/notes", nil))

	assert.Equal(t, http.StatusMethodNotAllowed, rr.Code,
		"an anonymous caller on an undeclared method gets the route-shape answer, not a challenge")
	assert.Empty(t, rr.Header().Get("WWW-Authenticate"),
		"no credential can make an undeclared method exist, so no challenge is offered")
	assert.Equal(t, "GET, HEAD", rr.Header().Get("Allow"))
	assert.False(t, *reached)
}
