package apitoken

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/kdex-tech/host-manager/internal/sign"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// A PAT records its subject's kind, and ValidateToken hands it back. See
// kdex-tech/host-manager#255.
func TestMintStatelessKey_RecordsSubjectKind(t *testing.T) {
	tm := subjectlessTokenManager(t)

	for _, kind := range []kdexv1alpha1.SubjectKind{kdexv1alpha1.SubjectKindClient, kdexv1alpha1.SubjectKindUser} {
		signed, err := tm.MintStatelessKey("https://a.example", "svc", kind, "read", "scope", time.Hour)
		require.NoError(t, err)

		data, err := tm.ValidateToken(context.Background(), signed, "https://a.example")
		require.NoError(t, err)
		assert.Equal(t, kind, data.SubjectKind)
	}
}

// A mint must name a kind this release knows: an empty one is a caller that
// lost track of it, and an unknown one cannot be enforced.
func TestMintStatelessKey_RefusesUnknownKind(t *testing.T) {
	tm := subjectlessTokenManager(t)

	for _, kind := range []kdexv1alpha1.SubjectKind{"", "ServiceAccount"} {
		token, err := tm.MintStatelessKey("https://a.example", "svc", kind, "read", "scope", time.Hour)
		assert.ErrorIs(t, err, ErrUnknownSubjectKind, "kind %q", kind)
		assert.Empty(t, token, "kind %q", kind)
	}
}

// TestValidateToken_KindlessTokenDecodes pins the tolerance of a PAT minted
// before PATs recorded their kind: it validates, with no kind. The token is
// signed with the manager's own key and every claim MintStatelessKey writes,
// except knd.
//
// LEGACY(#268): invert once ValidateToken refuses a kind-less PAT.
func TestValidateToken_KindlessTokenDecodes(t *testing.T) {
	tm := subjectlessTokenManager(t)

	data, err := tm.ValidateToken(context.Background(), signedPAT(tm, nil), "https://a.example")
	require.NoError(t, err)
	assert.Equal(t, "alice", data.Subject)
	assert.Empty(t, data.SubjectKind)
}

// TestValidateToken_RefusesNonStringKind: a knd that is present but not a
// string is malformed, and refused, unlike an absent one.
func TestValidateToken_RefusesNonStringKind(t *testing.T) {
	tm := subjectlessTokenManager(t)

	for name, knd := range map[string]any{
		"a number": 7, "an object": map[string]any{"k": "User"}, "a list": []string{"User"},
		"null": json.RawMessage("null"),
	} {
		data, err := tm.ValidateToken(context.Background(), signedPAT(tm, knd), "https://a.example")
		assert.Error(t, err, name)
		assert.Nil(t, data, name)
	}
}

// TestValidateToken_KindlessCostsWhatARecordedKindCosts (quad 2026-10-28,
// C): every live PAT is kind-less on the day this ships, so reading an
// absent knd must cost about what reading a present one does. Decoding every
// claim to learn knd is absent (go-paseto's Claims()) cost several times the
// allocations of the whole validation.
func TestValidateToken_KindlessCostsWhatARecordedKindCosts(t *testing.T) {
	tm := subjectlessTokenManager(t)
	allocs := func(knd any) float64 {
		pat := signedPAT(tm, knd)
		return testing.AllocsPerRun(50, func() {
			if _, err := tm.ValidateToken(context.Background(), pat, "https://a.example"); err != nil {
				t.Fatal(err)
			}
		})
	}
	recorded, kindless := allocs("User"), allocs(nil)
	t.Logf("allocations per validation: recorded knd %.0f, kind-less %.0f", recorded, kindless)
	assert.LessOrEqual(t, kindless, recorded+3, "a kind-less PAT allocates far more than a recorded one")
}

// BenchmarkValidateToken_Kind is the per-PAT cost of reading knd, for a PAT
// that records it and for a kind-less one.
func BenchmarkValidateToken_Kind(b *testing.B) {
	tm := subjectlessTokenManager(b)
	for name, knd := range map[string]any{"recorded": "User", "kind-less": nil} {
		pat := signedPAT(tm, knd)
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := tm.ValidateToken(context.Background(), pat, "https://a.example"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// signedPAT is a PAT for alice signed with tm's own key, carrying every claim
// MintStatelessKey writes except knd, which it sets to knd unless knd is nil.
func signedPAT(tm *TokenManager, knd any) string {
	now := time.Now()
	tok := paseto.NewToken()
	tok.SetAudience("https://a.example")
	tok.SetExpiration(now.Add(time.Hour))
	tok.SetString("iat", now.UTC().Format(time.RFC3339Nano))
	tok.SetIssuer("test-issuer")
	tok.SetJti(GenerateJTI("https://a.example", "alice", "read"))
	tok.SetNotBefore(now)
	tok.SetSubject("alice")
	tok.SetString("act", "read")
	tok.SetString("scp", "scope")
	if knd != nil {
		if err := tok.Set(sign.ClaimSubjectKind, knd); err != nil {
			panic(err)
		}
	}
	tok.SetFooter([]byte(`{"kid":"` + tm.activeKey.KeyId + `"}`))
	return tm.wrap(tok.V4Sign(*tm.activeKey.SecretKey, nil))
}
