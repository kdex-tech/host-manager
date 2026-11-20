package host

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// The migration #293 asks of a function that relied on implicit subtree
// pass-through: declare the subtree with a ServeMux catch-all key carrying its
// own security. This one declares the collection exactly, plus everything
// beneath one note's files, gated on that note.
func catchAllFn() *kdexv1alpha1.KDexFunction {
	return &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-notes", Namespace: "default"},
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
					"/api/v1/notes/{note_id}/files/{rest...}": {
						Get: &runtime.RawExtension{Raw: []byte(`{
							"operationId": "readNoteFile",
							"security": [{"bearer": [
								"functions:/api/v1/notes:read",
								"notes:{note_id}:read"
							]}]
						}`)},
					},
				},
			},
		},
	}
}

func serve(h http.Handler, method, target string, held []string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if held != nil {
		req = withHeld(req, held)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// A path deeper than a NON-wildcard key is undeclared, however much of it
// matches: a ServeMux pattern without a trailing slash or {name...} matches
// exactly. Holding every grant the function names changes nothing.
func TestGate_PathDeeperThanAnExactKeyIs404(t *testing.T) {
	held := []string{"functions:/api/v1/notes:read", "functions:/api/v1/notes:write"}
	for _, target := range []string{
		"/api/v1/notes/deeper",
		"/api/v1/notes/deeper/unknown",
		// The trailing slash is a different ServeMux path from the declared
		// "/api/v1/notes", and no redirect points from one to the other.
		"/api/v1/notes/",
	} {
		t.Run(target, func(t *testing.T) {
			h, reached := binderFixture(t, getOnlyFn())
			rr := serve(h, "GET", target, held)
			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.False(t, *reached, "an undeclared path must never reach the backend")
		})
	}
}

// The refusal depends only on the declared patterns, so it holds with no
// authorization checker configured at all -- the case where the gate block is
// skipped entirely and the fall-through proxied unconditionally.
//
// The fixture declares no security: building a handler for a secured operation
// needs a checker to parse it.
func TestGate_UndeclaredPathIs404WithoutAnAuthChecker(t *testing.T) {
	unsecured := func() *kdexv1alpha1.KDexFunction {
		fn := getOnlyFn()
		fn.Spec.API.Paths["/api/v1/notes"] = kdexv1alpha1.PathItem{
			Get: &runtime.RawExtension{Raw: []byte(`{"operationId": "listNotes"}`)},
		}
		return fn
	}

	code, _, reached := serveProxy(t, unsecured(), "/api/v1/notes/deeper/unknown")
	assert.Equal(t, http.StatusNotFound, code)
	assert.False(t, reached, "an undeclared path must never reach the backend")

	// Control: the declared path is still proxied under the same fixture.
	code, _, reached = serveProxy(t, unsecured(), "/api/v1/notes")
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, reached)
}

// The basePath is a route like any other: a function that does not declare it
// as a key does not serve it. The host mux still sends it here (it registers
// basePath and basePath+"/" for every function), so the function must refuse
// it itself. A single-segment wildcard does not match an empty segment, so the
// trailing-slash form is undeclared too.
func TestGate_UndeclaredBasePathIs404(t *testing.T) {
	held := []string{"functions:/api/v1/vector_stores:read", "vector_stores:vs_alice:read"}
	for _, target := range []string{"/api/v1/vector_stores", "/api/v1/vector_stores/"} {
		t.Run(target, func(t *testing.T) {
			h, reached := binderFixture(t, scopedStoreFn())
			rr := serve(h, "GET", target, held)
			assert.Equal(t, http.StatusNotFound, rr.Code)
			assert.False(t, *reached)
		})
	}
}

// A declared {name...} catch-all IS a route: everything beneath it is proxied,
// gated by THAT operation's security, with earlier path segments still bound.
func TestGate_DeclaredCatchAllServesItsSubtreeUnderItsOwnSecurity(t *testing.T) {
	const target = "/api/v1/notes/n1/files/a/b/c.txt"

	t.Run("held", func(t *testing.T) {
		h, reached := binderFixture(t, catchAllFn())
		rr := serve(h, "GET", target, []string{"functions:/api/v1/notes:read", "notes:n1:read"})
		assert.Equal(t, http.StatusOK, rr.Code)
		assert.True(t, *reached, "a declared subtree must be proxied")
	})

	t.Run("operation requirement not held", func(t *testing.T) {
		// The function-level grant alone -- all the old fall-through asked.
		h, reached := binderFixture(t, catchAllFn())
		rr := serve(h, "GET", target, []string{"functions:/api/v1/notes:read"})
		assert.Equal(t, http.StatusForbidden, rr.Code,
			"a declared route held without its entitlement is a denial, not a 404")
		assert.False(t, *reached)
	})

	t.Run("another note", func(t *testing.T) {
		// {note_id} is bound from the request, before the catch-all: a grant
		// on n2 does not reach n1's files.
		h, reached := binderFixture(t, catchAllFn())
		rr := serve(h, "GET", target, []string{"functions:/api/v1/notes:read", "notes:n2:read"})
		assert.Equal(t, http.StatusForbidden, rr.Code)
		assert.False(t, *reached)
	})

	t.Run("undeclared method", func(t *testing.T) {
		h, reached := binderFixture(t, catchAllFn())
		rr := serve(h, "DELETE", target, nil)
		assert.Equal(t, http.StatusMethodNotAllowed, rr.Code,
			"an undeclared method under a declared catch-all is still a 405")
		assert.Equal(t, "GET, HEAD", rr.Header().Get("Allow"))
		assert.False(t, *reached)
	})

	t.Run("sibling of the catch-all", func(t *testing.T) {
		// A catch-all declares ITS subtree, not the basePath's.
		h, reached := binderFixture(t, catchAllFn())
		rr := serve(h, "GET", "/api/v1/notes/n1/other", []string{"functions:/api/v1/notes:read", "notes:n1:read"})
		assert.Equal(t, http.StatusNotFound, rr.Code)
		assert.False(t, *reached)
	})
}

// ServeMux answers "/x" with a redirect to "/x/" when only a "/x/..." pattern
// matches, and Handler(r) reports THAT pattern for it. Such a request is
// treated as the declared route the redirect names: gated by its operation's
// security (never by empty requirements) and proxied, so a function that
// declares a trailing-slash subtree keeps serving the slashless form it always
// did. It is not a 404.
func TestGate_TrailingSlashRedirectIsGatedAsTheDeclaredSubtree(t *testing.T) {
	const target = "/api/v1/notes/n1/files" // the catch-all needs ".../files/"

	h, reached := binderFixture(t, catchAllFn())
	rr := serve(h, "GET", target, []string{"functions:/api/v1/notes:read", "notes:n1:read"})
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, *reached)

	h2, reached2 := binderFixture(t, catchAllFn())
	rr = serve(h2, "GET", target, []string{"functions:/api/v1/notes:read"})
	assert.Equal(t, http.StatusForbidden, rr.Code,
		"the redirect-matched request is held to the catch-all operation's requirements")
	assert.False(t, *reached2)
}

// An operation declared with NO security block is a declared route, not an
// undeclared one: it still reaches the empty-requirements branch, which asks
// for the function-level grant only. #293 must not turn it into a 404 or 500.
func TestGate_DeclaredOperationWithoutSecurityIsServed(t *testing.T) {
	fn := getOnlyFn()
	fn.Spec.API.Paths["/api/v1/notes"] = kdexv1alpha1.PathItem{
		Get: &runtime.RawExtension{Raw: []byte(`{"operationId": "listNotes"}`)},
	}

	h, reached := binderFixture(t, fn)
	rr := serve(h, "GET", "/api/v1/notes", []string{"functions:/api/v1/notes:read"})
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, *reached)

	// HEAD rides GET, which declares no security either.
	h2, reached2 := binderFixture(t, fn)
	rr = serve(h2, "HEAD", "/api/v1/notes", []string{"functions:/api/v1/notes:read"})
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, *reached2)
}

// The gate's requirements lookup separates "declared with no security" (empty
// requirements: the function-level grant) from "not declared at all" (nothing:
// the gate refuses). The second is unreachable through the handler -- the 404
// and 405 come first -- so it is pinned here directly: the old lookup answered
// both with empty requirements, which is how #291 and #293 were exposed.
func TestRouteRequirements_UndeclaredIsNeverEmptyRequirements(t *testing.T) {
	checker := auth.NewAuthorizationChecker(nil, logr.Discard())
	fh := &KDexFunctionHandler{
		parsedRequirements: map[string]entitlements.ParsedRequirements{
			"POST /x": checker.ParseRequirements([]kdexv1alpha1.SecurityRequirement{{"bearer": {"x:a:write"}}}),
		},
		declaredOps: map[string]struct{}{"GET /x": {}, "POST /x": {}},
	}

	_, key, ok := fh.routeRequirements(checker, "POST", "/x")
	assert.True(t, ok, "a secured declared operation")
	assert.Equal(t, "POST /x", key)
	_, key, ok = fh.routeRequirements(checker, "GET", "/x")
	assert.True(t, ok, "a declared operation without security gets empty requirements")
	assert.Equal(t, "GET /x", key)
	_, key, ok = fh.routeRequirements(checker, "HEAD", "/x")
	assert.True(t, ok, "an undeclared HEAD rides on GET")
	assert.Equal(t, "GET /x", key, "and uses GET's requirements and binding")

	_, _, ok = fh.routeRequirements(checker, "DELETE", "/x")
	assert.False(t, ok, "an undeclared method has no requirements to fall back to")
	_, _, ok = fh.routeRequirements(checker, "GET", "/y")
	assert.False(t, ok, "an undeclared pattern has no requirements to fall back to")
	_, _, ok = fh.routeRequirements(checker, "GET", "")
	assert.False(t, ok, "no matched pattern has no requirements to fall back to")
}

// An explicitly declared HEAD resolves to itself even when it declares no
// security and GET does: the lookup is on declarations, not on which
// operations happen to have parsed requirements.
func TestRouteRequirements_ExplicitHeadDoesNotInheritGet(t *testing.T) {
	checker := auth.NewAuthorizationChecker(nil, logr.Discard())
	fh := &KDexFunctionHandler{
		parsedRequirements: map[string]entitlements.ParsedRequirements{
			"GET /x": checker.ParseRequirements([]kdexv1alpha1.SecurityRequirement{{"bearer": {"x:a:read"}}}),
		},
		declaredOps: map[string]struct{}{"GET /x": {}, "HEAD /x": {}},
	}
	reqs, key, ok := fh.routeRequirements(checker, "HEAD", "/x")
	assert.True(t, ok)
	assert.Equal(t, "HEAD /x", key)
	assert.Equal(t, checker.ParseRequirements(nil), reqs, "HEAD's own, empty, requirements")
}

// Mounted the way the host mounts it -- basePath and basePath+"/" on the host
// ServeMux -- an undeclared path under the basePath DOES reach the function
// handler (the subtree pattern routes it there), and it is the function
// handler that refuses it. This is the census reproduction of #293: before the
// fix the request was proxied and the backend answered.
//
// The host mux also cleans the path first: a request with "//", "/./" or ".."
// is redirected to its clean form before any function handler runs, so the
// function's own pattern lookup only ever sees clean paths (except CONNECT,
// which ServeMux never cleans and which then matches no declared pattern).
func TestHostMux_UndeclaredSubtreePathReachesTheFunctionAndIs404(t *testing.T) {
	h, reached := binderFixture(t, getOnlyFn())
	hh := &HostHandler{log: logr.Discard()}
	mux := http.NewServeMux()
	routes := newRouteRegistry()
	hh.registerFunctionRoutes(mux, functionHandler{name: "fn-readonly", basePath: "/api/v1/notes", handler: h}, routes)

	held := []string{"functions:/api/v1/notes:read"}

	rr := serve(mux, "GET", "/api/v1/notes/deeper/unknown", held)
	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.False(t, *reached)

	rr = serve(mux, "GET", "/api/v1//notes", held)
	assert.Equal(t, http.StatusTemporaryRedirect, rr.Code, "the host mux cleans the path before routing")
	assert.Equal(t, "/api/v1/notes", rr.Header().Get("Location"))
	assert.False(t, *reached)

	rr = serve(mux, "CONNECT", "/api/v1/notes/./x", held)
	assert.Equal(t, http.StatusNotFound, rr.Code, "an uncleaned CONNECT path matches no declared pattern")
	assert.False(t, *reached)

	// Control: the declared route is served through the same mount.
	rr = serve(mux, "GET", "/api/v1/notes", held)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, *reached)
}
