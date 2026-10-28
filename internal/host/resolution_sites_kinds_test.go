package host

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

const kindsHostClientID = "svc-client"

// kindsClientConfig configures kindsHostClientID as an auth client, so the
// classifier reports its sub as a Client.
func kindsClientConfig() auth.Config {
	return auth.Config{Clients: map[string]auth.AuthClient{
		kindsHostClientID: {ClientID: kindsHostClientID, ClientSecret: "s3cret"},
	}}
}

// kindRecordingIDP records every BindingSubject a resolution site hands the
// role resolver.
type kindRecordingIDP struct {
	mu   sync.Mutex
	seen []auth.BindingSubject
}

func (p *kindRecordingIDP) FindInternal(string, string) (jwt.MapClaims, error) { return nil, nil }

func (p *kindRecordingIDP) FindInternalRolesAndEntitlements(bs auth.BindingSubject, _ *auth.BindingNames) ([]string, []string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, bs)
	return []string{}, []string{}, nil
}

func (p *kindRecordingIDP) take() []auth.BindingSubject {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := p.seen
	p.seen = nil
	return seen
}

// TestResolutionSites_PassKinds_HostSites is the internal/host half of
// auth.TestResolutionSites_PassKinds: the proxy PAT bridge and whoami hand
// the resolver the kind the credential carries. Each runs with a Client, a
// User, and a carried kind the classifier would contradict (alice carried as
// a Client), which must win (#255).
func TestResolutionSites_PassKinds_HostSites(t *testing.T) {
	cl, user := kdexv1alpha1.SubjectKindClient, kdexv1alpha1.SubjectKindUser
	expect := func(t *testing.T, seen []auth.BindingSubject, site string, kind kdexv1alpha1.SubjectKind) {
		t.Helper()
		require.NotEmpty(t, seen, "site %q resolved no roles", site)
		for _, bs := range seen {
			assert.Equal(t, site, bs.Site)
			assert.Equal(t, kind, bs.Kind, "site %q", site)
		}
	}
	carried := []struct {
		name string
		sub  string
		kind kdexv1alpha1.SubjectKind
	}{
		{"a Client", kindsHostClientID, cl},
		{"a User", "alice", user},
		{"a carried kind wins over the classifier", "alice", cl},
	}

	t.Run("proxy pat", func(t *testing.T) {
		idp := &kindRecordingIDP{}
		handler, tm, _, _ := apitokenBridgeFixtureFor(t, apiKeySecuredFunction("/v1/api", true), idp,
			kindsClientConfig(), nil)
		for _, tc := range carried {
			t.Run(tc.name, func(t *testing.T) {
				token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, tc.sub, tc.kind, "act", "s", time.Hour)
				require.NoError(t, err)

				req := httptest.NewRequest(http.MethodGet, "/v1/api", nil)
				req.Header.Set("X-API-TOKEN", token)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				require.Equal(t, http.StatusOK, rec.Code)
				expect(t, idp.take(), auth.SiteProxyPAT, tc.kind)
			})
		}
	})

	t.Run("whoami", func(t *testing.T) {
		idp := &kindRecordingIDP{}
		ex, err := auth.NewExchanger(t.Context(), kindsClientConfig(), nil, idp, nil)
		require.NoError(t, err)
		whoami := func(ac auth.AuthContext) {
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
			req = req.WithContext(auth.SetAuthContext(req.Context(), ac))
			(&HostHandler{}).writeWhoamiRPC(httptest.NewRecorder(), req, []byte("1"), ex)
		}
		for _, tc := range carried {
			t.Run(tc.name, func(t *testing.T) {
				whoami(auth.AuthContext{"sub": tc.sub, auth.ClaimSubjectKind: string(tc.kind)})
				expect(t, idp.take(), auth.SiteWhoami, tc.kind)
			})
		}
		t.Run("a kind-less context falls back to the classifier", func(t *testing.T) { // LEGACY(#268)
			whoami(auth.AuthContext{"sub": kindsHostClientID})
			expect(t, idp.take(), auth.SiteWhoami, cl)
		})
	})
}
