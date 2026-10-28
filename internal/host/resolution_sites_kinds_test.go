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
// the resolver the sub's classified kind, a Client for a configured client.
func TestResolutionSites_PassKinds_HostSites(t *testing.T) {
	expect := func(t *testing.T, seen []auth.BindingSubject, site string) {
		t.Helper()
		require.NotEmpty(t, seen, "site %q resolved no roles", site)
		for _, bs := range seen {
			assert.Equal(t, site, bs.Site)
			assert.Equal(t, kdexv1alpha1.SubjectKindClient, bs.Kind, "site %q", site)
		}
	}

	t.Run("proxy pat", func(t *testing.T) {
		idp := &kindRecordingIDP{}
		handler, tm, _, _ := apitokenBridgeFixtureFor(t, apiKeySecuredFunction("/v1/api", true), idp,
			kindsClientConfig(), nil)
		token, err := tm.MintStatelessKey(apitokenBridgeHostAudience, kindsHostClientID, "act", "s", time.Hour)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/v1/api", nil)
		req.Header.Set("X-API-TOKEN", token)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		expect(t, idp.take(), auth.SiteProxyPAT)
	})

	t.Run("whoami", func(t *testing.T) {
		idp := &kindRecordingIDP{}
		ex, err := auth.NewExchanger(t.Context(), kindsClientConfig(), nil, idp, nil)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
		req = req.WithContext(auth.SetAuthContext(req.Context(), auth.AuthContext{"sub": kindsHostClientID}))
		rec := httptest.NewRecorder()
		(&HostHandler{}).writeWhoamiRPC(rec, req, []byte("1"), ex)
		expect(t, idp.take(), auth.SiteWhoami)
	})
}
