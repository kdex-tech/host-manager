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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
)

// TestReverseProxyHandler_FailsClosedWhenSignerCannotBeBuilt covers the
// unchecked error at the sign.NewSigner call in reverseProxyHandler.
//
// NewSigner returns (nil, error) for an empty audience, a zero duration, an
// empty issuer, a nil private key or an empty key id. The error was assigned
// and never read, so `signer` stayed nil and the handler was built anyway --
// and the Rewrite closure dereferences it on EVERY request through that
// function's proxy. The result is a panic per request, recovered by net/http
// as a dropped connection, rather than a diagnosable response. The two sibling
// failures in the same function (a bad function URL, a bad mapper) both return
// an error handler; this one did not.
func TestReverseProxyHandler_FailsClosedWhenSignerCannotBeBuilt(t *testing.T) {
	logf.SetLogger(logr.Discard())

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	fn := &kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-nosigner", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API:     kdexv1alpha1.API{BasePath: "/v1/nosigner"},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{URL: upstream.URL},
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv
	cacheManager, _ := cache.NewCacheManager("", "signer-fail-test", nil)

	hh := &HostHandler{
		log:          logr.Discard(),
		cacheManager: cacheManager,
		authConfig: &auth.Config{
			// An empty KeyId is one of NewSigner's five refusal conditions.
			ActivePair: &keys.KeyPair{ActiveKey: true, KeyId: "", Private: signerKey},
		},
	}

	handler := hh.reverseProxyHandler(fn, "https://test-host.example.com")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/nosigner", nil))

	assert.Equal(t, http.StatusInternalServerError, rec.Code,
		"a proxy that could not build its FAT signer must fail closed with a "+
			"diagnosable 500, not serve traffic and dereference a nil signer")
}
