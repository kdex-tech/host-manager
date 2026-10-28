package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kdex.dev/crds/api/v1alpha1"
)

// The veto (#255): current config is a veto on a credential's kind, never its
// source. The scenarios, one per path a removed client could take, are in
// internal/host (TestVeto_*); these pin the rules and the log line.

const vetoRemovedClient = "removed-client"

// newVetoExchanger is an Exchanger whose registry remembers
// vetoRemovedClient, configured on a first build and gone from the second,
// with kindsClientID still configured.
func newVetoExchanger(t *testing.T) *Exchanger {
	t.Helper()
	cm, err := cache.NewCacheManager("", "veto-rules", nil)
	require.NoError(t, err)
	_, err = newRegistryExchanger(t, cm, kindsClientID, vetoRemovedClient)
	require.NoError(t, err)
	ex, err := newRegistryExchanger(t, cm, kindsClientID)
	require.NoError(t, err)
	return ex
}

// captureVetoLog swaps the veto logger for a funcr sink at V(0) for the rest
// of the test. No test in this package runs in parallel.
func captureVetoLog(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	prev := vetoLog
	vetoLog = funcr.New(func(prefix, args string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.buf.WriteString(prefix + " " + args + "\n")
	}, funcr.Options{Verbosity: 0})
	t.Cleanup(func() { vetoLog = prev })
	return c
}

func TestVetoSubjectKind(t *testing.T) {
	ex := newVetoExchanger(t)
	user, cl := v1alpha1.SubjectKindUser, v1alpha1.SubjectKindClient

	for _, tc := range []struct {
		name    string
		sub     string
		kind    v1alpha1.SubjectKind
		refused bool
	}{
		{"a Client that is configured", kindsClientID, cl, false},
		{"a Client that was removed", vetoRemovedClient, cl, true},
		{"a Client that was never configured", "alice", cl, true},
		{"a Client named like a registered (DCR) client", "dcr_abc", cl, true},
		{"a User", "alice", user, false},
		{"a User named like a configured client", kindsClientID, user, true},
		{"a User named like a removed client", vetoRemovedClient, user, true},
		{"a User named like a registered (DCR) client", "dcr_abc", user, true},
		{"a kind this release does not know", vetoRemovedClient, "ServiceAccount", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ex.VetoSubjectKind(tc.sub, tc.kind)
			if tc.refused {
				require.ErrorIs(t, err, ErrCredentialKindRefused)
				assert.NotContains(t, err.Error(), tc.sub, "the refusal names the rule, never the sub")
			} else {
				assert.NoError(t, err)
			}
		})
	}

	var nilEx *Exchanger
	assert.ErrorIs(t, nilEx.VetoSubjectKind(kindsClientID, cl), ErrCredentialKindRefused,
		"no config configures no client")
	assert.NoError(t, nilEx.VetoSubjectKind("alice", user))
}

// TestVeto_LogNamesRuleAndSite pins the refusal's one V(0) line at each
// acceptance site in this package: it names the rule and the site, never the
// sub, which may be an email under RoleBindingClaim (#215).
func TestVeto_LogNamesRuleAndSite(t *testing.T) {
	const email = "alice@acme.io"
	cfg, ex, tm, cs := newKindsSiteExchanger(t, &kindRecordingProvider{})

	lines := func(c *logCapture) []string {
		return strings.Split(strings.TrimSpace(c.String()), "\n")
	}
	expectOneLine := func(t *testing.T, c *logCapture, site string) {
		t.Helper()
		got := lines(c)
		require.Len(t, got, 1, "one line per refusal: %q", c.String())
		assert.Contains(t, got[0], `"site"="`+site+`"`)
		assert.Contains(t, got[0], `"rule"=`)
		assert.NotContains(t, got[0], email)
	}

	t.Run("the PAT helper", func(t *testing.T) {
		c := captureVetoLog(t)
		_, err := ex.PATAuthContext(context.Background(),
			&apitoken.TokenData{Subject: email, SubjectKind: v1alpha1.SubjectKindClient}, SiteProxyPAT)
		require.ErrorIs(t, err, ErrCredentialKindRefused)
		expectOneLine(t, c, SiteProxyPAT)
	})

	t.Run("the host PAT middleware", func(t *testing.T) {
		c := captureVetoLog(t)
		pat, err := tm.MintStatelessKey(cfg.Audience, email, v1alpha1.SubjectKindClient, "read", "", time.Hour)
		require.NoError(t, err)
		_, ok := cfg.hostPATIdentity(context.Background(), pat, ex)
		assert.False(t, ok)
		expectOneLine(t, c, SiteHostPAT)
	})

	t.Run("token exchange", func(t *testing.T) {
		c := captureVetoLog(t)
		fatSigner, err := sign.NewSigner("https://fn-a.example", time.Hour, "test-iss", &cs, "test-kid", nil)
		require.NoError(t, err)
		fat, err := fatSigner.Sign(jwt.MapClaims{"sub": email, ClaimSubjectKind: "Client"})
		require.NoError(t, err)
		_, err = ex.ExchangeSubjectToken(fat, "https://fn-b.example")
		require.ErrorIs(t, err, ErrCredentialKindRefused)
		assert.NotErrorIs(t, err, ErrServerError)
		expectOneLine(t, c, SiteTokenExchange)
	})

	t.Run("the host JWT gate", func(t *testing.T) {
		c := captureVetoLog(t)
		tok, err := cfg.Signer.Sign(jwt.MapClaims{"sub": email, ClaimSubjectKind: "Client"})
		require.NoError(t, err)
		reached := false
		gate := cfg.WithAuthentication(ex)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.False(t, reached)
		expectOneLine(t, c, SiteHostJWT)
	})
}
