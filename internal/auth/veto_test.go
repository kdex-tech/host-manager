package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
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

// captureVetoLog swaps the veto logger for a funcr sink at V(1), the
// refusals' level, for the rest of the test. No test in this package runs in
// parallel.
func captureVetoLog(t *testing.T) *logCapture {
	t.Helper()
	return captureVetoLogAt(t, 1)
}

func captureVetoLogAt(t *testing.T, v int) *logCapture {
	t.Helper()
	c := &logCapture{}
	prev := vetoLog
	vetoLog = funcr.New(func(prefix, args string) {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.buf.WriteString(prefix + " " + args + "\n")
	}, funcr.Options{Verbosity: v})
	t.Cleanup(func() { vetoLog = prev })
	return c
}

func TestVeto_Rules(t *testing.T) {
	// No client here was ever removed but vetoRemovedClient, so iat does not
	// matter but for it; TestVeto_ReaddedClient pins the cutoff.
	const iat = 1
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
			err := ex.vetoSubjectKind(tc.sub, tc.kind, iat)
			if tc.refused {
				require.ErrorIs(t, err, ErrCredentialKindRefused)
				assert.NotContains(t, err.Error(), tc.sub, "the refusal names the rule, never the sub")
			} else {
				assert.NoError(t, err)
			}
		})
	}

	var nilEx *Exchanger
	assert.ErrorIs(t, nilEx.vetoSubjectKind(kindsClientID, cl, iat), ErrCredentialKindRefused,
		"no config configures no client")
	assert.NoError(t, nilEx.vetoSubjectKind("alice", user, iat))
}

// TestVeto_LogNamesRuleAndSite pins the refusal's one V(1) line at each
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
		_, err := ex.PATAuthContext(
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
		// The gate's own rejection line goes to the request's logger. A
		// veto refusal is the veto's line alone, so it writes none (B).
		var gateLog strings.Builder
		reqLog := funcr.New(func(prefix, args string) { gateLog.WriteString(prefix + " " + args + "\n") },
			funcr.Options{Verbosity: 1})
		tok, err := cfg.Signer.Sign(jwt.MapClaims{"sub": email, ClaimSubjectKind: "Client"})
		require.NoError(t, err)
		reached := false
		gate := cfg.WithAuthentication(ex)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req = req.WithContext(logr.NewContext(req.Context(), reqLog))
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		gate.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
		assert.False(t, reached)
		expectOneLine(t, c, SiteHostJWT)
		assert.NotContains(t, gateLog.String(), "token is not valid", "the gate logged the refusal a second time")
		assert.NotContains(t, gateLog.String(), email)
	})
}

// TestVeto_RefusalIsNotLoggedAtV0 (B, Ruling Q1): a refusal is logged at
// V(1), like every other credential rejection, so a removed client's retry
// loop cannot flood the V(0) log (#181).
func TestVeto_RefusalIsNotLoggedAtV0(t *testing.T) {
	ex := newVetoExchanger(t)
	c := captureVetoLogAt(t, 0)
	require.ErrorIs(t, ex.VetoCredential(vetoRemovedClient, v1alpha1.SubjectKindClient, 1, SiteHostJWT),
		ErrCredentialKindRefused)
	assert.Empty(t, c.String())
}

// TestVeto_ReaddedClient (A1, a user decision): a client removed and added
// back is a clean slate. Its credentials issued at or before the removal
// stay refused; one issued after it is accepted. A credential without a
// usable iat is refused once the client was ever removed, and accepted for
// a client never removed. Each removal moves the cutoff forward.
func TestVeto_ReaddedClient(t *testing.T) {
	cl := v1alpha1.SubjectKindClient
	cm, err := cache.NewCacheManager("", "veto-readd", nil)
	require.NoError(t, err)

	ex := buildAt(t, cm, 100, kindsClientID, "never-removed")
	for _, iat := range []int64{0, 50, 100} {
		assert.NoError(t, ex.vetoSubjectKind(kindsClientID, cl, iat), "never removed, iat %d", iat)
	}

	buildAt(t, cm, 200, "never-removed")
	ex = buildAt(t, cm, 300, kindsClientID, "never-removed")
	for _, tc := range []struct {
		iat     int64
		refused bool
	}{{0, true}, {150, true}, {200, true}, {201, false}, {300, false}} {
		err := ex.vetoSubjectKind(kindsClientID, cl, tc.iat)
		if tc.refused {
			assert.ErrorIs(t, err, ErrCredentialKindRefused, "iat %d", tc.iat)
		} else {
			assert.NoError(t, err, "iat %d", tc.iat)
		}
	}
	assert.NoError(t, ex.vetoSubjectKind("never-removed", cl, 0), "a client never removed")

	buildAt(t, cm, 400, "never-removed")
	ex = buildAt(t, cm, 500, kindsClientID, "never-removed")
	assert.ErrorIs(t, ex.vetoSubjectKind(kindsClientID, cl, 300), ErrCredentialKindRefused,
		"issued between the two removals")
	assert.NoError(t, ex.vetoSubjectKind(kindsClientID, cl, 401))
}

// TestVeto_EveryKnownKindHasARule (E): every kind this release knows has a
// veto rule, so none passes the veto by omission.
func TestVeto_EveryKnownKindHasARule(t *testing.T) {
	for _, kind := range v1alpha1.SubjectKinds {
		assert.NotNil(t, vetoRules[kind], "kind %q has no veto rule", kind)
	}
}

// TestVeto_KnownKindWithoutARuleIsRefused (E): a kind this release knows
// but has no rule for fails closed, while a kind it does not know passes
// (it can only narrow).
func TestVeto_KnownKindWithoutARuleIsRefused(t *testing.T) {
	ex := newVetoExchanger(t)
	user := v1alpha1.SubjectKindUser
	rule := vetoRules[user]
	delete(vetoRules, user)
	t.Cleanup(func() { vetoRules[user] = rule })

	err := ex.vetoSubjectKind("alice", user, 1)
	require.ErrorIs(t, err, ErrCredentialKindRefused)
	assert.ErrorIs(t, err, errNoVetoRule)
	assert.NoError(t, ex.vetoSubjectKind("alice", "ServiceAccount", 1), "an unknown kind passes")
}
