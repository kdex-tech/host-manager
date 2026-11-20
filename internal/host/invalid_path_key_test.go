package host

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A spec.api.paths key ServeMux refuses -- an invalid pattern, or one that
// conflicts with a sibling key -- made the function's pattern mux panic at
// handler build, out of every RebuildMux: one tenant's KDexFunction took down
// the host's whole route rebuild. The function is instead not routed (its
// paths 404) and every other function on the host keeps serving.
func TestRebuildMux_InvalidOrConflictingPathKeyFailsClosed(t *testing.T) {
	op := func() *runtime.RawExtension { return &runtime.RawExtension{Raw: []byte(`{}`)} }
	get := kdexv1alpha1.PathItem{Get: op()}

	for name, paths := range map[string]map[string]kdexv1alpha1.PathItem{
		"bad wildcard":           {"/bad/v1/{": get},
		"catch-all not last":     {"/bad/{rest...}/x": get},
		"ambiguous":              {"/bad/{a}/x": get, "/bad/x/{b}": get},
		"same shape, other name": {"/bad/x/{a}": get, "/bad/x/{b}": get},
	} {
		t.Run(name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "upstream")
			}))
			t.Cleanup(upstream.Close)

			hh := newTestHostHandler(t, "en", []string{"en"})
			hh.host.Routing.Domains = []string{"example.com"}
			hh.scheme = "https"
			hh.authConfig = challengeFixtureAuthConfig(t)

			bad := readyFunction("bad", "/bad", upstream.URL)
			bad.Spec.API.Paths = paths
			hh.functions = []kdexv1alpha1.KDexFunction{bad, readyFunction("good", "/good", upstream.URL)}

			require.NotPanics(t, hh.RebuildMux)

			mux := hh.Mux
			for _, p := range []string{"/bad", "/bad/x/y", "/bad/v1/z"} {
				rr := doRequest(t, mux, "GET", p)
				assert.Equal(t, http.StatusNotFound, rr.Code, p)
				assert.NotEqual(t, "upstream", rr.Body.String(), p)
			}
			assert.Equal(t, "upstream", doRequest(t, mux, "GET", "/good/z").Body.String(),
				"a sibling function on the same host still serves")
		})
	}
}

// The gate parses each secured operation's requirements with hh.authChecker
// when the handler is built. With no checker that dereferenced nil -- and a
// plain nil-guard would be worse: the request gate is skipped when there is no
// checker, so the secured operation would be proxied ungated. A function
// declaring security on a host with no checker is not routed at all.
func TestReverseProxyHandler_SecuredOpWithoutAuthCheckerFailsClosed(t *testing.T) {
	var h http.Handler
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
	}))
	t.Cleanup(upstream.Close)

	fn := getOnlyFn() // its GET declares security
	fn.Status.URL = upstream.URL
	hh := &HostHandler{log: logr.Discard(), authConfig: challengeFixtureAuthConfig(t)}
	hh.cacheManager = newTestHostHandler(t, "en", []string{"en"}).cacheManager
	require.Nil(t, hh.authChecker)

	require.NotPanics(t, func() { h = hh.reverseProxyHandler(fn, "https://test-host.example.com") })
	_, isFunctionHandler := h.(*KDexFunctionHandler)
	assert.False(t, isFunctionHandler, "a secured function with no checker must not be routable")

	// Mounted as rebuildMuxSnapshot mounts it: not at all, so the path 404s.
	mux := http.NewServeMux()
	if fh, ok := h.(*KDexFunctionHandler); ok {
		hh.registerFunctionRoutes(mux, functionHandler{name: fn.Name, basePath: fn.Spec.API.BasePath, handler: fh}, newRouteRegistry())
	}
	rr := serve(mux, "GET", "/api/v1/notes", []string{"functions:/api/v1/notes:read"})
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.False(t, reached, "the backend must never be reached ungated")
}

// An EXPLICITLY declared HEAD is its own operation: it is gated by its own
// (here, empty) requirements, not GET's. Only an undeclared HEAD rides on GET.
func TestGate_ExplicitHeadUsesItsOwnRequirements(t *testing.T) {
	// GET requires an entitlement the caller does not hold.
	securedGet := func() *kdexv1alpha1.KDexFunction {
		fn := getOnlyFn()
		fn.Spec.API.Paths["/api/v1/notes"] = kdexv1alpha1.PathItem{
			Get: &runtime.RawExtension{Raw: []byte(`{"security": [{"bearer": ["notes:special:read"]}]}`)},
		}
		return fn
	}
	held := []string{"functions:/api/v1/notes:read"}

	// Explicit HEAD, no security: the function-level grant is enough.
	fn := securedGet()
	item := fn.Spec.API.Paths["/api/v1/notes"]
	item.Head = &runtime.RawExtension{Raw: []byte(`{"operationId": "headNotes"}`)}
	fn.Spec.API.Paths["/api/v1/notes"] = item
	h, reached := binderFixture(t, fn)
	rr := serve(h, "HEAD", "/api/v1/notes", held)
	assert.Equal(t, http.StatusOK, rr.Code, "an explicit HEAD is gated by its own requirements")
	assert.True(t, *reached)

	// Control: an undeclared HEAD still rides on GET's requirements.
	h2, reached2 := binderFixture(t, securedGet())
	rr = serve(h2, "HEAD", "/api/v1/notes", held)
	assert.Equal(t, http.StatusForbidden, rr.Code, "an implicit HEAD is held to GET's requirements")
	assert.False(t, *reached2)
}
