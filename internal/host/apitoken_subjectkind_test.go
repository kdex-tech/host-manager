package host

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/golang-jwt/jwt/v5"
	entitlements "github.com/kdex-tech/entitlements/go"
	"github.com/kdex-tech/host-manager/internal"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// The credential carries its subject's kind (knd) from issue on, and every
// site that resolves roles from a credential uses it. See
// kdex-tech/host-manager#255.

const (
	kindsHost      = "kinds-host"
	kindsNamespace = "kinds-ns"
	kindsUserRole  = "user-role"
	kindsCliRole   = "client-role"
)

// kindsRoleProvider is the REAL role provider over a fake client holding a
// `*` binding narrowed to each kind, so every result depends on the matcher.
func kindsRoleProvider(t *testing.T) auth.InternalIdentityProvider {
	t.Helper()
	return roleProviderFor(t,
		roleGrant{name: "people", subject: "*", role: kindsUserRole, kinds: []kdexv1alpha1.SubjectKind{kdexv1alpha1.SubjectKindUser}},
		roleGrant{name: "machines", subject: "*", role: kindsCliRole, kinds: []kdexv1alpha1.SubjectKind{kdexv1alpha1.SubjectKindClient}},
	)
}

// roleGrant is one KDexRoleBinding granting role to subject, narrowed to
// kinds when any are given.
type roleGrant struct {
	name, subject, role string
	kinds               []kdexv1alpha1.SubjectKind
}

// roleProviderFor is the REAL role provider over a fake client holding each
// grant's binding, and one KDexRole per role granting read on itself.
func roleProviderFor(t *testing.T, grants ...roleGrant) auth.InternalIdentityProvider {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(s))
	require.NoError(t, kdexv1alpha1.AddToScheme(s))

	var objs []client.Object
	for _, grant := range grants {
		objs = append(objs,
			&kdexv1alpha1.KDexRoleBinding{
				ObjectMeta: metav1.ObjectMeta{Name: grant.name, Namespace: kindsNamespace},
				Spec: kdexv1alpha1.KDexRoleBindingSpec{
					HostRef:      corev1.LocalObjectReference{Name: kindsHost},
					Subject:      grant.subject,
					Roles:        []string{grant.role},
					SubjectKinds: grant.kinds,
				},
			},
			&kdexv1alpha1.KDexRole{
				ObjectMeta: metav1.ObjectMeta{Name: grant.role, Namespace: kindsNamespace},
				Spec: kdexv1alpha1.KDexRoleSpec{
					HostRef: corev1.LocalObjectReference{Name: kindsHost},
					Rules:   []kdexv1alpha1.PolicyRule{{Resources: []string{grant.role}, Verbs: []string{"read"}}},
				},
			})
	}
	byHost := func(o client.Object) []string {
		switch v := o.(type) {
		case *kdexv1alpha1.KDexRoleBinding:
			return []string{v.Spec.HostRef.Name}
		case *kdexv1alpha1.KDexRole:
			return []string{v.Spec.HostRef.Name}
		}
		return nil
	}
	c := fake.NewClientBuilder().WithScheme(s).
		WithIndex(&kdexv1alpha1.KDexRoleBinding{}, internal.HOST_INDEX_KEY, byHost).
		WithIndex(&kdexv1alpha1.KDexRole{}, internal.HOST_INDEX_KEY, byHost).
		WithObjects(objs...).Build()

	sp, err := auth.NewRoleProvider(context.Background(), c, kindsHost, kindsNamespace, nil)
	require.NoError(t, err)
	return sp
}

// acRecordingChecker captures the whole auth context the proxy gate reads.
type acRecordingChecker struct {
	mockAuthChecker
	ac auth.AuthContext
}

func (c *acRecordingChecker) GetParsedEntitlements(ctx context.Context) entitlements.ParsedEntitlements {
	if ac, ok := auth.GetAuthContext(ctx); ok {
		c.ac = maps.Clone(ac)
	}
	return c.mockAuthChecker.GetParsedEntitlements(ctx)
}

// TestPATAuthContext_MiddlewareAndProxyAgree: the host PAT middleware and the
// proxy PAT bridge build one PAT's context through the same helper, so they
// agree on everything the credential decides.
func TestPATAuthContext_MiddlewareAndProxyAgree(t *testing.T) {
	idp := kindsRoleProvider(t)
	rec := &acRecordingChecker{}
	handler, tm, _, _ := apitokenBridgeFixtureFor(t, apiKeySecuredFunction("/v1/api", true), idp,
		kindsClientConfig(), nil, rec)
	pat, err := tm.MintStatelessKey(apitokenBridgeHostAudience, kindsHostClientID,
		kdexv1alpha1.SubjectKindClient, "act", "s", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v1/api", nil)
	req.Header.Set("X-API-TOKEN", pat)
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)
	proxyAC := rec.ac
	require.NotNil(t, proxyAC, "the proxy gate saw no auth context")

	ex, err := auth.NewExchanger(t.Context(), kindsClientConfig(), nil, idp, nil)
	require.NoError(t, err)
	cfg := &auth.Config{TokenManager: tm, Audience: apitokenBridgeHostAudience}
	var hostAC auth.AuthContext
	mw := cfg.WithAPITokenIdentity(ex)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		hostAC, _ = auth.GetAuthContext(r.Context())
	}))
	req = httptest.NewRequest(http.MethodGet, "/-/check", nil)
	req.Header.Set("Authorization", "Bearer "+pat)
	mw.ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, hostAC, "the middleware built no auth context")

	assert.Equal(t, hostAC["sub"], proxyAC["sub"])
	assert.Equal(t, hostAC[auth.ClaimSubjectKind], proxyAC[auth.ClaimSubjectKind])
	assert.Equal(t, stringSliceFromClaim(hostAC["roles"]), stringSliceFromClaim(proxyAC["roles"]))
	assert.Equal(t, stringSliceFromClaim(hostAC["entitlements"]), stringSliceFromClaim(proxyAC["entitlements"]))

	assert.Equal(t, "Client", hostAC[auth.ClaimSubjectKind])
	assert.Equal(t, []string{kindsCliRole}, stringSliceFromClaim(hostAC["roles"]))
}

// mintedKind mints through /-/apitokens/mint as caller and returns the kind
// the PAT records.
func mintedKind(t *testing.T, hh *HostHandler, caller map[string]any, sub string) kdexv1alpha1.SubjectKind {
	t.Helper()
	rr := mintFor(t, hh, caller, sub)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp MintResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	data, err := hh.authConfig.TokenManager.ValidateToken(t.Context(), resp.Token, "aud")
	require.NoError(t, err)
	return data.SubjectKind
}

// withGrant is caller holding the self-service mint grant too.
func withGrant(caller map[string]any) map[string]any {
	caller = maps.Clone(caller)
	caller["entitlements"] = append(stringsAsAny(stringSliceFromClaim(caller["entitlements"])), selfServiceGrant...)
	return caller
}

func stringsAsAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// TestSelfMint_RecordsCallerKind: a self-mint records the kind of the
// credential minting, not a re-classification of its sub.
func TestSelfMint_RecordsCallerKind(t *testing.T) {
	hh := provisioningHost(t, provisioningLookup{})

	t.Run("a client authenticated by client_credentials", func(t *testing.T) {
		caller := withGrant(realClientCaller(t, hh))
		require.Equal(t, "Client", caller[auth.ClaimSubjectKind], "precondition: the token carries its kind")
		assert.Equal(t, kdexv1alpha1.SubjectKindClient, mintedKind(t, hh, caller, orchestrator))
	})

	t.Run("a kind-less client_credentials context", func(t *testing.T) { // LEGACY(#268)
		assert.Equal(t, kdexv1alpha1.SubjectKindClient, mintedKind(t, hh, withGrant(clientCaller()), orchestrator))
	})

	t.Run("a user", func(t *testing.T) {
		caller := withGrant(map[string]any{"sub": "alice", auth.ClaimSubjectKind: "User"})
		assert.Equal(t, kdexv1alpha1.SubjectKindUser, mintedKind(t, hh, caller, "alice"))
	})

	t.Run("a kind-less user context", func(t *testing.T) { // LEGACY(#268)
		assert.Equal(t, kdexv1alpha1.SubjectKindUser, mintedKind(t, hh, withGrant(map[string]any{"sub": "alice"}), "alice"))
	})

	// The cases above agree with the classifier; these two do not, so they
	// are what pins that a self-mint takes the caller's own kind rather than
	// SubjectKindOf(sub).
	t.Run("a kind-less client_credentials context for a client no longer configured", func(t *testing.T) { // LEGACY(#268)
		// The classifier calls removed-client a User, but its credential
		// is a client_credentials token, so the PAT records Client. Reachable
		// only through the LEGACY path, ahead of the auth gate's veto of a
		// Client credential whose client is not configured; the test drives
		// the mint handler with a constructed context, so it stays valid.
		caller := withGrant(map[string]any{"sub": "removed-client", "grant_type": auth.GRANT_TYPE_CLIENT_CREDENTIALS})
		require.Equal(t, kdexv1alpha1.SubjectKindUser, hh.authExchanger.SubjectKindOf("removed-client"),
			"precondition: the classifier disagrees")
		assert.Equal(t, kdexv1alpha1.SubjectKindClient, mintedKind(t, hh, caller, "removed-client"))
	})

	t.Run("a carried kind contradicting its sub", func(t *testing.T) {
		// The gate vetoes such a credential (a User named like a client,
		// #255); the test drives the mint handler with a constructed
		// context, so it stays valid.
		caller := withGrant(map[string]any{"sub": orchestrator, auth.ClaimSubjectKind: "User"})
		require.Equal(t, kdexv1alpha1.SubjectKindClient, hh.authExchanger.SubjectKindOf(orchestrator),
			"precondition: the classifier disagrees")
		assert.Equal(t, kdexv1alpha1.SubjectKindUser, mintedKind(t, hh, caller, orchestrator))
	})
}

// provisioningRoleProvider resolves roles through the real role provider and
// provisioning through a provisioningLookup.
type provisioningRoleProvider struct {
	roles  auth.InternalIdentityProvider
	lookup provisioningLookup
}

func (p provisioningRoleProvider) FindInternal(sub, pw string) (jwt.MapClaims, error) {
	return p.roles.FindInternal(sub, pw)
}

func (p provisioningRoleProvider) FindInternalRolesAndEntitlements(bs auth.BindingSubject, n *auth.BindingNames) ([]string, []string, error) {
	return p.roles.FindInternalRolesAndEntitlements(bs, n)
}

func (p provisioningRoleProvider) ResolveClaimsWithError(sub string) (jwt.MapClaims, error) {
	return p.lookup.ResolveClaimsWithError(sub)
}

// TestMint_ProvisionedUserRecordsUser is Review Focus 4: a client minting for
// a user it provisioned produces a User PAT, which gets the [User] grants and
// none of the client's.
func TestMint_ProvisionedUserRecordsUser(t *testing.T) {
	hh := provisioningHost(t, provisioningRoleProvider{roles: kindsRoleProvider(t), lookup: sandbox(orchestrator)})

	rr := mintFor(t, hh, clientCaller(), "sandbox-1")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var resp MintResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	data, err := hh.authConfig.TokenManager.ValidateToken(t.Context(), resp.Token, "aud")
	require.NoError(t, err)
	assert.Equal(t, kdexv1alpha1.SubjectKindUser, data.SubjectKind)

	ac, err := hh.authExchanger.PATAuthContext(data, auth.SiteHostPAT)
	require.NoError(t, err)
	assert.Equal(t, []string{kindsUserRole}, stringSliceFromClaim(ac["roles"]))
}

// TestProxyFAT_CarriesKind: the FAT the proxy projects from a Client PAT
// carries knd, and a token exchange of that FAT resolves as the Client, so
// it does not pick up a `*` binding narrowed to [User].
func TestProxyFAT_CarriesKind(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	exCfg := kindsClientConfig()
	exCfg.ActivePair = &keys.KeyPair{ActiveKey: true, KeyId: "test-kid", Private: crypto.Signer(priv)}
	exCfg.Issuer = "https://api-host.example.com"
	exCfg.Audience = apitokenBridgeHostAudience
	exCfg.TokenTTL = time.Hour

	idp := kindsRoleProvider(t)
	handler, tm, fatHeader, _ := apitokenBridgeFixtureFor(t, apiKeySecuredFunction("/v1/api", true), idp, exCfg, nil)
	pat, err := tm.MintStatelessKey(apitokenBridgeHostAudience, kindsHostClientID,
		kdexv1alpha1.SubjectKindClient, "act", "s", time.Hour)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v1/api", nil)
	req.Header.Set("X-API-TOKEN", pat)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	fat := decodeFAT(t, *fatHeader)
	assert.Equal(t, "Client", fat[auth.ClaimSubjectKind])

	ex, err := auth.NewExchanger(t.Context(), exCfg, nil, idp, nil)
	require.NoError(t, err)
	ts, err := ex.ExchangeSubjectToken(strings.TrimPrefix(*fatHeader, "Bearer "), "https://fn-b.example")
	require.NoError(t, err)
	exchanged := decodeFAT(t, "Bearer "+ts.AccessToken)
	assert.Equal(t, []string{kindsCliRole}, stringSliceFromClaim(exchanged["roles"]))
	assert.Equal(t, "Client", exchanged[auth.ClaimSubjectKind])
}

// TestWhoami_UsesContextKind: whoami reports what the credential's own kind
// is entitled to, the same kind enforcement used.
func TestWhoami_UsesContextKind(t *testing.T) {
	idp := kindsRoleProvider(t)
	ex, err := auth.NewExchanger(t.Context(), kindsClientConfig(), nil, idp, nil)
	require.NoError(t, err)
	patAC, err := ex.PATAuthContext(
		&apitoken.TokenData{Subject: kindsHostClientID, SubjectKind: kdexv1alpha1.SubjectKindClient}, auth.SiteProxyPAT)
	require.NoError(t, err)

	whoami := func(t *testing.T, ac auth.AuthContext) []string {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
		req = req.WithContext(auth.SetAuthContext(req.Context(), ac))
		rec := httptest.NewRecorder()
		(&HostHandler{}).writeWhoamiRPC(rec, req, []byte("1"), ex)
		var resp struct {
			Result struct {
				StructuredContent WhoamiResult `json:"structuredContent"`
			} `json:"result"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		return resp.Result.StructuredContent.Entitlements
	}
	userOnly, clientOnly := kindsUserRole+"::read", kindsCliRole+"::read"

	for name, ac := range map[string]auth.AuthContext{
		"a Client PAT": patAC,
		"a client_credentials context": {
			"sub": kindsHostClientID, "grant_type": auth.GRANT_TYPE_CLIENT_CREDENTIALS,
			auth.ClaimSubjectKind: "Client",
		},
		// LEGACY(#268): a token from before knd, for a client no longer
		// configured, is still a Client by its grant.
		"a kind-less client_credentials context": {
			"sub": "removed-client", "grant_type": auth.GRANT_TYPE_CLIENT_CREDENTIALS,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := whoami(t, ac)
			assert.NotContains(t, got, userOnly)
			assert.Contains(t, got, clientOnly)
		})
	}

	t.Run("a user", func(t *testing.T) {
		got := whoami(t, auth.AuthContext{"sub": "alice", auth.ClaimSubjectKind: "User"})
		assert.Contains(t, got, userOnly)
		assert.NotContains(t, got, clientOnly)
	})
}

// TestVerify_OmitsEmptyKind: /-/apitokens/verify reports a PAT's knd, and has
// no knd key for a PAT that records none.
func TestVerify_OmitsEmptyKind(t *testing.T) {
	hh, tm := crossSubjectHost(t)
	hh.authConfig.Audience = "aud"

	verify := func(t *testing.T, token string) map[string]any {
		t.Helper()
		body, _ := json.Marshal(VerifyRequest{Token: token})
		rec := httptest.NewRecorder()
		hh.apitokenVerifyHandler(rec, httptest.NewRequest(http.MethodPost, "/-/apitokens/verify", bytes.NewBuffer(body)))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		got := map[string]any{}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
		return got
	}

	t.Run("a new token", func(t *testing.T) {
		token, err := tm.MintStatelessKey("aud", "alice", kdexv1alpha1.SubjectKindUser, "read", "", time.Hour)
		require.NoError(t, err)
		assert.Equal(t, "User", verify(t, token)["knd"])
	})

	t.Run("a kind-less token", func(t *testing.T) { // LEGACY(#268)
		got := verify(t, kindlessPAT("issuer", "aud", "alice"))
		assert.Equal(t, "alice", got["sub"])
		assert.NotContains(t, got, "knd")
	})
}

// kindlessPAT is a PAT as a release before #255 minted it: signed with the
// dev key pair a test TokenManager validates with, carrying every claim a
// mint writes except knd. LEGACY(#268).
func kindlessPAT(issuer, aud, sub string) string {
	pair := (*apitoken.GenerateDevmodeKeyPair())[0]
	now := time.Now()
	tok := paseto.NewToken()
	tok.SetAudience(aud)
	tok.SetExpiration(now.Add(time.Hour))
	tok.SetIssuedAt(now)
	tok.SetIssuer(issuer)
	tok.SetJti(apitoken.GenerateJTI(aud, sub, "read"))
	tok.SetNotBefore(now)
	tok.SetSubject(sub)
	tok.SetString("act", "read")
	tok.SetString("scp", "")
	tok.SetFooter([]byte(`{"kid":"` + pair.KeyId + `"}`))
	return tok.V4Sign(*pair.SecretKey, nil)
}
