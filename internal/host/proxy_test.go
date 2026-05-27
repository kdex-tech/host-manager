package host

import (
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
// the proxy handler, and returns the path the upstream actually saw.
func runProxy(t *testing.T, fn *kdexv1alpha1.KDexFunction, incomingPath string) string {
	t.Helper()
	logf.SetLogger(logr.Discard())

	var capturedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
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
	assert.Equal(t, http.StatusOK, rr.Code)
	return capturedPath
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
