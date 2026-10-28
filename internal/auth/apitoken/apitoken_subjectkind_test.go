package apitoken

import (
	"context"
	"testing"
	"time"

	"aidanwoods.dev/go-paseto"
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
	tok.SetFooter([]byte(`{"kid":"` + tm.activeKey.KeyId + `"}`))
	kindless := tm.wrap(tok.V4Sign(*tm.activeKey.SecretKey, nil))

	data, err := tm.ValidateToken(context.Background(), kindless, "https://a.example")
	require.NoError(t, err)
	assert.Equal(t, "alice", data.Subject)
	assert.Empty(t, data.SubjectKind)
}
