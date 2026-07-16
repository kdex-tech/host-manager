package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// binderFixture builds a reverse-proxy handler for fn with a REAL
// AuthorizationChecker, and returns the handler plus a flag reporting whether
// the upstream was reached (i.e. the gate passed).
//
// runProxy (proxy_test.go) cannot exercise the gate: it builds a HostHandler
// with a nil authChecker, so the whole gate block is skipped. This fixture
// therefore supplies a real checker -- the binder's deny path is only
// meaningful against the real entitlements implementation.
func binderFixture(t *testing.T, fn *kdexv1alpha1.KDexFunction) (http.Handler, *bool) {
	t.Helper()
	logf.SetLogger(logr.Discard())

	reached := new(bool)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*reached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)
	fn.Status.URL = upstream.URL

	// keys.KeyPair.Private is a crypto.Signer; P-256 mirrors the existing
	// apitokenBridgeFixture and keygen is instant.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv

	cacheManager, err := cache.NewCacheManager("", "binder-test", nil)
	require.NoError(t, err)

	// No TokenManager and no apiKey/oauth2 scheme on these fixtures, so the
	// PASETO bridge never runs and authExchanger may stay nil.
	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cacheManager,
		authChecker:  auth.NewAuthorizationChecker(nil, logr.Discard()),
		authConfig: &auth.Config{
			ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: signerKey},
		},
	}
	return hh.reverseProxyHandler(fn, "https://test-host.example.com"), reached
}

// scopedStoreFn is a function whose GET op is path-scoped and declares a
// {vector_store_id} placeholder -- the shape the CR migration will adopt.
func scopedStoreFn() *kdexv1alpha1.KDexFunction {
	return &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-stores", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: "/api/v1/vector_stores",
				Paths: map[string]kdexv1alpha1.PathItem{
					"/api/v1/vector_stores/{vector_store_id}": {
						Get: &runtime.RawExtension{Raw: []byte(`{
							"operationId": "getStore",
							"security": [{"bearer": [
								"functions:/api/v1/vector_stores:read",
								"vector_stores:{vector_store_id}:read"
							]}]
						}`)},
					},
				},
			},
		},
	}
}

// requestAs drives one request through the handler carrying `held`
// entitlements.
//
// auth.AuthContext is a jwt.MapClaims (map[string]any) and has no
// SetEntitlements method: entitlements ride under the "entitlements" claim,
// which AuthContext.GetEntitlements reads and GetParsedEntitlements buckets
// under the "bearer" scheme -- matching the fixtures' security blocks.
func requestAs(t *testing.T, h http.Handler, method, path string, held []string, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ac := auth.AuthContext{"sub": "tester", "entitlements": held}
	req = req.WithContext(auth.SetAuthContext(req.Context(), ac))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// The entitlements#4 regression: a caller holding ONE store must not pass a
// {vector_store_id} gate while addressing a DIFFERENT store. Pre-binding, the
// requirement was vector_stores:*:read and any single grant satisfied it.
func TestGate_BindsPathPlaceholder_DeniesOtherStore(t *testing.T) {
	h, reached := binderFixture(t, scopedStoreFn())
	held := []string{"functions:/api/v1/vector_stores:read", "vector_stores:vs_alice:all"}

	code := requestAs(t, h, "GET", "/api/v1/vector_stores/vs_alice", held, nil)
	assert.Equal(t, http.StatusOK, code, "own store must pass")
	assert.True(t, *reached)

	*reached = false
	code = requestAs(t, h, "GET", "/api/v1/vector_stores/vs_bob", held, nil)
	assert.NotEqual(t, http.StatusOK, code, "another store must DENY -- this is entitlements#4")
	assert.False(t, *reached, "upstream must not be reached")
}

// An unbound placeholder must DENY even for a wildcard holder. Without the
// bind-error branch this silently admits every wildcard holder, because an
// unbound placeholder is an ordinary literal and a wildcard matches any literal.
func TestGate_UnboundPlaceholderDenies(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-ingest", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: "/api/v1/ingest",
				Paths: map[string]kdexv1alpha1.PathItem{
					"/api/v1/ingest": {
						Post: &runtime.RawExtension{Raw: []byte(`{
							"operationId": "ingest",
							"security": [{"bearer": [
								"functions:/api/v1/ingest:create",
								"vector_stores:{vector_store_id}:write"
							]}],
							"x-entitlement-binding": {
								"vector_store_id": [{"in": "header", "name": "X-Vector-Store-Id"}]
							}
						}`)},
					},
				},
			},
		},
	}
	h, reached := binderFixture(t, fn)
	// The `functions:` grant must use the `all` verb: the gate's identity
	// requirement is built as functions:<basePath>:read (verb defaults to
	// "read"), so a `create`-only grant would deny on IDENTITY and never reach
	// the placeholder -- passing the assertion below for the wrong reason and
	// hiding the very hole this test exists to prove.
	held := []string{"functions:/api/v1/ingest:all", "vector_stores::all"} // wildcard holder

	code := requestAs(t, h, "POST", "/api/v1/ingest", held, nil) // no header -> unbound
	assert.NotEqual(t, http.StatusOK, code, "unbound placeholder must deny even a wildcard holder")
	assert.False(t, *reached)

	*reached = false
	code = requestAs(t, h, "POST", "/api/v1/ingest", held, map[string]string{"X-Vector-Store-Id": "vs_abc"})
	assert.Equal(t, http.StatusOK, code, "a bound header must pass for a wildcard holder")
}

// Additivity: a CR with no {param} must behave exactly as before.
func TestGate_NoPlaceholderIsUnchanged(t *testing.T) {
	fn := scopedStoreFn()
	fn.Spec.API.Paths["/api/v1/vector_stores/{vector_store_id}"] = kdexv1alpha1.PathItem{
		Get: &runtime.RawExtension{Raw: []byte(`{
			"operationId": "getStore",
			"security": [{"bearer": ["functions:/api/v1/vector_stores:read"]}]
		}`)},
	}
	h, _ := binderFixture(t, fn)
	held := []string{"functions:/api/v1/vector_stores:read"}
	assert.Equal(t, http.StatusOK, requestAs(t, h, "GET", "/api/v1/vector_stores/vs_bob", held, nil))
}
