package host

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/keys"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/stretchr/testify/require"
)

// newReadyFunctionOAuth2AndAPIKeyNoBearer declares oauth2 + apiKeyHeader and
// deliberately NO bearer alternative. This is the shape that exposes whether
// the PAT-bridge entitlements mirror is intact.
//
// Both omissions matter:
//   - WITHOUT apiKeyHeader the function would be oauth2-only, and the bridge
//     excludes the host audience from expectedAuds unless acceptsAPIKey — so a
//     host-audience PAT was never reachable there and the test would prove
//     nothing about the mirror.
//   - WITH bearer (as newReadyFunctionWithOAuth2AndAPIKey has it) a PAT
//     satisfies the requirement straight from the default bucket, so the test
//     passes with or without the mirror. That is one of the two reasons the
//     earlier guard was vacuous.
//
// oauth2 is therefore the only satisfiable alternative, and only the mirror can
// satisfy it: nothing in the codebase ever populates an apiKey* bucket.
func newReadyFunctionOAuth2AndAPIKeyNoBearer(_ *testing.T, basePath string, scopes []string) kdexv1alpha1.KDexFunction {
	scopeJSON, _ := json.Marshal(scopes)
	s := string(scopeJSON)
	raw := []byte(`{"security":[{"oauth2":` + s + `},{"apiKeyHeader":` + s + `}],"responses":{"200":{"description":"ok"}}}`)
	return kdexv1alpha1.KDexFunction{
		ObjectMeta: metav1.ObjectMeta{Name: "fn-oauth2-apikey-nobearer", Namespace: "default"},
		Spec: kdexv1alpha1.KDexFunctionSpec{
			HostRef: corev1.LocalObjectReference{Name: "h"},
			API: kdexv1alpha1.API{
				BasePath: basePath,
				Paths:    map[string]kdexv1alpha1.PathItem{basePath: {Post: &runtime.RawExtension{Raw: raw}}},
			},
		},
		Status: kdexv1alpha1.KDexFunctionStatus{State: kdexv1alpha1.KDexFunctionStateReady},
	}
}

// realGateFixture builds the proxy with the REAL auth.AuthorizationChecker and
// the REAL WithAuthentication middleware in front, i.e. production's
// composition.
//
// The existing patProxyFixture* helpers wire entitlementGateChecker, whose
// CheckAccess returns true unconditionally and which never evaluates declared
// requirements. Any assertion about scheme buckets made through that stub is
// vacuous.
func realGateFixture(t *testing.T, fn kdexv1alpha1.KDexFunction, idp auth.InternalIdentityProvider) (http.Handler, *apitoken.TokenManager, *bool) {
	t.Helper()
	logf.SetLogger(logr.Discard())

	backendReached := new(bool)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*backendReached = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signerKey crypto.Signer = priv

	cm, err := cache.NewCacheManager("", "pat-realgate-test", nil)
	require.NoError(t, err)

	tm, err := apitoken.NewTokenManager(patProxyIssuer, apitoken.GenerateDevmodeKeyPair(), nil)
	require.NoError(t, err)

	ex, err := auth.NewExchanger(t.Context(), auth.Config{}, cm, idp)
	require.NoError(t, err)

	fn.Status.URL = upstream.URL

	authConfig := &auth.Config{
		ActivePair:   &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: signerKey},
		Audience:     patProxyHostAud,
		Issuer:       patProxyIssuer,
		CookieName:   "auth_token",
		TokenManager: tm,
	}

	hh := &HostHandler{
		log:           logr.Discard(),
		scheme:        "https",
		cacheManager:  cm,
		authChecker:   auth.NewAuthorizationChecker(nil, logr.Discard()),
		host:          &kdexv1alpha1.KDexHostSpec{Routing: kdexv1alpha1.Routing{Domains: []string{patProxyDomain}}},
		functions:     []kdexv1alpha1.KDexFunction{fn},
		authConfig:    authConfig,
		authExchanger: ex,
	}

	inner := hh.reverseProxyHandler(&fn, patProxyIssuer)
	return authConfig.WithAuthentication(ex)(inner), tm, backendReached
}

// TestProxyPAT_HostAudiencePAT_ReachesOAuth2DeclaredFunction is the guard
// proxy_pat_middleware_test.go was meant to be.
//
// aa73843 made `Authorization: Bearer <developer key>` work on an
// oauth2-protected function. The mechanism is the PAT bridge marking its
// identity with PATBridgeClaim, which mirrors the caller's entitlements into
// the "oauth2" scheme bucket — the ONLY thing that can satisfy an
// oauth2-declared requirement, since nothing in the codebase ever populates an
// apiKey* bucket.
//
// When the auth middleware authenticates the PAT itself, the bridge's
// `!alreadyLoggedIn` guard makes it step aside, and an unmarked identity leaves
// that bucket empty. satisfiesAndRequirements then fails closed and the caller
// gets 401 on a function that worked before.
func TestProxyPAT_HostAudiencePAT_ReachesOAuth2DeclaredFunction(t *testing.T) {
	scopes := []string{"functions:" + patProxyBasePath + ":read"}
	idp := stubInternalIdentityProvider{
		roles: []string{"mcp-role"},
		ents:  []string{"functions:" + patProxyBasePath + ":read"},
	}

	handler, tm, backendReached := realGateFixture(t,
		newReadyFunctionOAuth2AndAPIKeyNoBearer(t, patProxyBasePath, scopes), idp)

	pat, err := tm.MintStatelessKey(patProxyHostAud, "mcp-bob", "act", "scope:x", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, patProxyBasePath, nil)
	req.Header.Set("Authorization", "Bearer "+pat)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	require.True(t, *backendReached,
		"a host-audience PAT must still reach a function whose only satisfiable alternative is "+
			"oauth2-declared; losing the PAT-bridge "+
			"entitlements mirror regresses aa73843")
	require.Equal(t, http.StatusOK, rec.Code)
}
