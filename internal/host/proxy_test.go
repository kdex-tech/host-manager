package host

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
