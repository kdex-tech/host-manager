package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// runProxy starts a capturing upstream HTTP server, points fn.Status.URL at it
// (preserving the original path component as a backend mount path), invokes
// the proxy handler, and returns the ESCAPED path the upstream actually saw —
// the form its router matches on, so a %2F or an encoded ".." stays visible.
func runProxy(t *testing.T, fn *kdexv1alpha1.KDexFunction, incomingPath string) string {
	t.Helper()
	code, capturedPath, _ := serveProxy(t, fn, incomingPath)
	assert.Equal(t, http.StatusOK, code)
	return capturedPath
}

// serveProxy is runProxy without the status assertion: it returns the gate's
// status code, the ESCAPED path the upstream saw, and whether the upstream was
// reached at all.
func serveProxy(t *testing.T, fn *kdexv1alpha1.KDexFunction, incomingPath string) (int, string, bool) {
	t.Helper()
	logf.SetLogger(logr.Discard())

	var capturedPath string
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.EscapedPath()
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	// Preserve any path component in the original fn.Status.URL so the proxy's
	// path-join behavior still applies. Swap only the scheme://host:port.
	origURL, err := url.Parse(fn.Status.URL)
	if err == nil && origURL.Host != "" {
		newURL, _ := url.Parse(upstream.URL)
		origURL.Scheme = newURL.Scheme
		origURL.Host = newURL.Host
		fn.Status.URL = origURL.String()
	} else {
		fn.Status.URL = upstream.URL
	}

	// reverseProxyHandler unconditionally calls sign.NewSigner with
	// &hh.authConfig.ActivePair.Private, which nil-derefs without a real key
	// pair. The signer is only USED when a request is authenticated; an
	// anonymous request like ours never touches it, but we still need the
	// fields populated so the constructor runs without panicking.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cacheManager, _ := cache.NewCacheManager("", "proxy-test", nil)
	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cacheManager,
		authConfig: &auth.Config{
			ActivePair: &keys.KeyPair{
				ActiveKey: true,
				KeyId:     "test-kid",
				Private:   privateKey,
			},
		},
	}

	handler := hh.reverseProxyHandler(fn, "https://test-host.example.com")
	req := httptest.NewRequest("GET", incomingPath, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Code, capturedPath, reached
}

func TestProxy_KnativeFunction_PassesPathThrough(t *testing.T) {
	// Knative-deployed function: no Backend; Status.URL is a Knative DNS name
	// with empty path. Generated function code is expected to handle basePath.
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-knative", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/docs"},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{URL: "http://fn-xyz.kdex-knative.svc.cluster.local"},
	}

	got := runProxy(t, fn, "/v1/docs/find")
	assert.Equal(t, "/v1/docs/find", got, "Knative path must be preserved")
}

func TestProxy_ServiceBacked_StripsBasePathAndPrependsBackendPath(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-knowdb", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/docs"},
			Backend: &kdexv1alpha1.FunctionBackend{
				Type:    kdexv1alpha1.FunctionBackendTypeService,
				Service: &kdexv1alpha1.ServiceBackend{Name: "knowdb", Port: intstr.FromInt(8080), Path: "/api"},
			},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "http://knowdb.default.svc.cluster.local:8080/api",
		},
	}

	// /v1/docs stripped, /api prepended -> /api/find
	got := runProxy(t, fn, "/v1/docs/find")
	assert.Equal(t, "/api/find", got)
}

func TestProxy_ServiceBacked_NoBackendPath_DefaultsToRoot(t *testing.T) {
	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-knowdb-root", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/docs"},
			Backend: &kdexv1alpha1.FunctionBackend{
				Type:    kdexv1alpha1.FunctionBackendTypeService,
				Service: &kdexv1alpha1.ServiceBackend{Name: "knowdb", Port: intstr.FromInt(8080)},
			},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{
			URL: "http://knowdb.default.svc.cluster.local:8080/",
		},
	}

	// /v1/docs stripped, / from backend defaults -> /find
	got := runProxy(t, fn, "/v1/docs/find")
	assert.Equal(t, "/find", got)
}

// The gate matches and binds the route on the ESCAPED path, so the upstream
// must receive exactly those segments. Rebuilding the upstream path from the
// decoded one turned every %2F into a real '/', so the upstream served a
// different route (or instance) from the one the gate authorized.
func TestProxy_UpstreamGetsTheEscapedPathTheGateMatched(t *testing.T) {
	knative := func() *kdexv1alpha1.KDexFunction {
		return &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "fn-knative", Namespace: "default"},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				HostRef: corev1.LocalObjectReference{Name: "h"},
				API:     kdexv1alpha1.API{BasePath: "/v1/roles"},
			},
			Status: kdexv1alpha1.KDexFunctionStatus{URL: "http://fn-xyz.kdex-knative.svc.cluster.local"},
		}
	}
	service := func() *kdexv1alpha1.KDexFunction {
		return &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "fn-svc", Namespace: "default"},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				HostRef: corev1.LocalObjectReference{Name: "h"},
				API:     kdexv1alpha1.API{BasePath: "/v1/roles"},
				Backend: &kdexv1alpha1.FunctionBackend{
					Type:    kdexv1alpha1.FunctionBackendTypeService,
					Service: &kdexv1alpha1.ServiceBackend{Name: "svc", Port: intstr.FromInt(8080), Path: "/api"},
				},
			},
			Status: kdexv1alpha1.KDexFunctionStatus{URL: "http://svc.default.svc.cluster.local:8080/api"},
		}
	}

	for _, tc := range []struct {
		name string
		fn   func() *kdexv1alpha1.KDexFunction
		in   string
		want string
	}{
		{"knative: encoded slash kept", knative, "/v1/roles/a%2Fb", "/v1/roles/a%2Fb"},
		{"service: encoded slash kept", service, "/v1/roles/a%2Fb", "/api/a%2Fb"},
		{"service: dots inside a segment are not a dot-segment", service, "/v1/roles/a..b", "/api/a..b"},
		{"service: double-encoded percent kept", service, "/v1/roles/a%2525", "/api/a%2525"},
		{"service: trailing slash kept", service, "/v1/roles/find/", "/api/find/"},
		{"service: base path alone maps to the mount", service, "/v1/roles", "/api"},
		{"service: base path with slash maps to the mount with slash", service, "/v1/roles/", "/api/"},
		{"service: base path in another encoding still strips", service, "/v1/%72oles/find", "/api/find"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, runProxy(t, tc.fn(), tc.in))
		})
	}
}

// A ".." segment is refused before anything else, encoded or not. Spelled
// %2E%2E%2F inside one segment, ServeMux matches it as a single mapped route
// segment, and the decoded path then climbed out of the function's base path
// (and its backend's mount path): GET /api/v1/files/%2E%2E%2F%2E%2E%2Finternal
// reached knowdb's unauthenticated /internal/* through the files route.
func TestProxy_RefusesDotDotSegments(t *testing.T) {
	fn := func() *kdexv1alpha1.KDexFunction {
		return &kdexv1alpha1.KDexFunction{
			ObjectMeta: metav1.ObjectMeta{Name: "fn-svc", Namespace: "default"},
			Spec: kdexv1alpha1.KDexFunctionSpec{
				HostRef: corev1.LocalObjectReference{Name: "h"},
				API:     kdexv1alpha1.API{BasePath: "/api/v1/files"},
				Backend: &kdexv1alpha1.FunctionBackend{
					Type:    kdexv1alpha1.FunctionBackendTypeService,
					Service: &kdexv1alpha1.ServiceBackend{Name: "knowdb", Port: intstr.FromInt(8080), Path: "/v1/files"},
				},
			},
			Status: kdexv1alpha1.KDexFunctionStatus{URL: "http://knowdb.default.svc.cluster.local:8080/v1/files"},
		}
	}

	for _, p := range []string{
		"/api/v1/files/%2E%2E%2F%2E%2E%2Finternal%2Fvalidate",
		"/api/v1/files/%2e%2e%2finternal",
		"/api/v1/files/%2E%2E",
		"/api/v1/files/..%2Finternal",
		"/api/v1/files/a%2F..%2Fb",
		"/api/v1/files/a/%2E%2E/b",
	} {
		t.Run(p, func(t *testing.T) {
			code, _, reached := serveProxy(t, fn(), p)
			assert.Equal(t, http.StatusBadRequest, code)
			assert.False(t, reached, "a dot-dot request must never reach the upstream")
		})
	}

	for _, p := range []string{"/api/v1/files/a..b", "/api/v1/files/..a", "/api/v1/files/a.."} {
		t.Run("allowed "+p, func(t *testing.T) {
			code, _, reached := serveProxy(t, fn(), p)
			assert.Equal(t, http.StatusOK, code)
			assert.True(t, reached)
		})
	}
}

func TestNewProxyTransport_ZeroValueAppliesDefaults(t *testing.T) {
	tr := newProxyTransport(ProxyTimeouts{})

	assert.Equal(t, defaultProxyResponseHeaderTimeout, tr.ResponseHeaderTimeout)
	assert.Equal(t, defaultProxyIdleConnTimeout, tr.IdleConnTimeout)
	// DialContext is a closure — covered indirectly by the override test below
	// and by the integration-level proxy tests above; here we only assert
	// it's wired.
	assert.NotNil(t, tr.DialContext)
}

func TestNewProxyTransport_HonorsOverrides(t *testing.T) {
	want := ProxyTimeouts{
		DialTimeout:           7 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		IdleConnTimeout:       45 * time.Second,
	}

	tr := newProxyTransport(want)

	assert.Equal(t, want.ResponseHeaderTimeout, tr.ResponseHeaderTimeout)
	assert.Equal(t, want.IdleConnTimeout, tr.IdleConnTimeout)
}

func TestNewProxyTransport_PartialOverridesGetMixedDefaults(t *testing.T) {
	tr := newProxyTransport(ProxyTimeouts{
		ResponseHeaderTimeout: 3 * time.Minute,
	})

	assert.Equal(t, 3*time.Minute, tr.ResponseHeaderTimeout)
	assert.Equal(t, defaultProxyIdleConnTimeout, tr.IdleConnTimeout)
}

func TestNewProxyTransport_NegativeValuesTreatedAsZero(t *testing.T) {
	tr := newProxyTransport(ProxyTimeouts{
		ResponseHeaderTimeout: -1 * time.Second,
	})

	assert.Equal(t, defaultProxyResponseHeaderTimeout, tr.ResponseHeaderTimeout)
}

func TestHostHandler_SetProxyTimeouts(t *testing.T) {
	hh := &HostHandler{}
	want := ProxyTimeouts{ResponseHeaderTimeout: 90 * time.Second}

	got := hh.SetProxyTimeouts(want)

	assert.Same(t, hh, got, "SetProxyTimeouts must return the receiver for chaining")
	assert.Equal(t, want, hh.proxyTimeouts)
}

// TestProxy_FATCacheHitsWhenOnlyVolatileHeadersVary regression-tests #37.
// Two authenticated requests with the SAME identity but DIFFERENT volatile
// headers (Traceparent, X-Request-Id) must produce the SAME downstream
// Authorization header — i.e., the cache hits on the second call. Pre-fix
// (when the cache key hashed the full request headers) the cache missed
// and the second call minted a fresh JWT with different iat/jti.
func TestProxy_FATCacheHitsWhenOnlyVolatileHeadersVary(t *testing.T) {
	logf.SetLogger(logr.Discard())

	// Upstream captures the Authorization header per call.
	var seen []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-cache", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/cache"},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{URL: upstream.URL},
	}

	// ECDSA P-256 — faster sign than the 2048-bit RSA used elsewhere, and
	// matches the host-manager devMode keypair shape.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv

	cacheManager, _ := cache.NewCacheManager("", "fat-cache-test", nil)
	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cacheManager,
		authConfig: &auth.Config{
			ActivePair: &keys.KeyPair{
				ActiveKey: true,
				KeyId:     "test-kid",
				Private:   signerKey,
			},
		},
	}

	handler := hh.reverseProxyHandler(fn, "https://test-host.example.com")

	authedCtx := auth.SetAuthContext(t.Context(), auth.AuthContext{
		"sub":          "user-42",
		"entitlements": []string{"functions:cache:read"},
		"roles":        []string{"reader"},
	})

	send := func(traceparent, requestID string) {
		req := httptest.NewRequestWithContext(authedCtx, "GET", "/v1/cache/ping", nil)
		req.Header.Set("Traceparent", traceparent)
		req.Header.Set("X-Request-Id", requestID)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
	}

	send("00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01", "req-1")
	// Sleep so iat would shift if the second call re-signed (iat is seconds).
	time.Sleep(1100 * time.Millisecond)
	send("00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01", "req-2")

	require.Len(t, seen, 2, "upstream must have received exactly two requests")
	assert.NotEmpty(t, seen[0], "first call must have an Authorization header")
	assert.Equal(t, seen[0], seen[1],
		"cache must hit on the second call — volatile headers (Traceparent / X-Request-Id) "+
			"must not invalidate the FAT cache key")
}
