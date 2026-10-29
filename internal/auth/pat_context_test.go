package auth

import (
	"context"
	"testing"

	"github.com/kdex-tech/host-manager/internal/auth/apitoken"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kdex.dev/crds/api/v1alpha1"
)

// newPATKindsExchanger is an Exchanger over the real role provider, with a
// `*` binding narrowed to each kind and kindsClientID configured as a client.
func newPATKindsExchanger(t *testing.T) *Exchanger {
	t.Helper()
	sp := newKindsScopeProvider(t, nil,
		kindsBinding("people", "*", "user-role", v1alpha1.SubjectKindUser),
		kindsBinding("machines", "*", "client-role", v1alpha1.SubjectKindClient),
	)
	ex, err := NewExchanger(context.Background(), Config{Clients: map[string]AuthClient{
		kindsClientID: {ClientID: kindsClientID, ClientSecret: "s3cret"},
	}}, nil, sp, nil)
	require.NoError(t, err)
	return ex
}

// TestPATAuthContext_Kind pins where a PAT's kind comes from: the kind it
// recorded, else (a PAT minted before PATs recorded one) the classifier. The
// context carries the kind it resolved with. See kdex-tech/host-manager#255.
func TestPATAuthContext_Kind(t *testing.T) {
	ex := newPATKindsExchanger(t)

	for _, tc := range []struct {
		name     string
		data     apitoken.TokenData
		wantKind v1alpha1.SubjectKind
		wantRole string
	}{
		{
			name:     "a recorded Client",
			data:     apitoken.TokenData{Subject: kindsClientID, SubjectKind: v1alpha1.SubjectKindClient},
			wantKind: v1alpha1.SubjectKindClient, wantRole: "client-role",
		},
		{
			// LEGACY(#268)
			name:     "a kind-less PAT for a configured client",
			data:     apitoken.TokenData{Subject: kindsClientID},
			wantKind: v1alpha1.SubjectKindClient, wantRole: "client-role",
		},
		{
			// LEGACY(#268)
			name:     "a kind-less PAT for a user",
			data:     apitoken.TokenData{Subject: "alice"},
			wantKind: v1alpha1.SubjectKindUser, wantRole: "user-role",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ac, err := ex.PATAuthContext(&tc.data, SiteHostPAT)
			require.NoError(t, err)
			assert.Equal(t, string(tc.wantKind), ac[ClaimSubjectKind])
			roles, err := ac.GetRoles()
			require.NoError(t, err)
			assert.Equal(t, []string{tc.wantRole}, roles)
			assert.Equal(t, tc.data.Subject, ac["sub"])
		})
	}

	// A recorded known kind the classifier contradicts is what the veto
	// refuses (#255): it once won over the classifier, and is now refused
	// before anything resolves. A recorded kind still wins where the veto
	// lets it through: an unknown one, below.
	for _, data := range []apitoken.TokenData{
		{Subject: "alice", SubjectKind: v1alpha1.SubjectKindClient},
		{Subject: kindsClientID, SubjectKind: v1alpha1.SubjectKindUser},
	} {
		t.Run("a recorded "+string(data.SubjectKind)+" its sub contradicts is vetoed", func(t *testing.T) {
			ac, err := ex.PATAuthContext(&data, SiteHostPAT)
			require.ErrorIs(t, err, ErrCredentialKindRefused)
			assert.Nil(t, ac)
		})
	}

	t.Run("a recorded unknown kind is carried, and matches only unnarrowed bindings", func(t *testing.T) {
		ac, err := ex.PATAuthContext(
			&apitoken.TokenData{Subject: "robot", SubjectKind: "ServiceAccount"}, SiteHostPAT)
		require.NoError(t, err)
		assert.Equal(t, "ServiceAccount", ac[ClaimSubjectKind])
		roles, err := ac.GetRoles()
		require.NoError(t, err)
		assert.Empty(t, roles, "neither narrowed binding matches a kind this release does not know")
	})
}

// TestContextSubjectKind pins the one fallback chain for a credential's
// kind: the kind it carries, else Client for a client_credentials token, else
// the classifier. The last two are LEGACY(#268).
func TestContextSubjectKind(t *testing.T) {
	ex := newPATKindsExchanger(t)
	user, cl := v1alpha1.SubjectKindUser, v1alpha1.SubjectKindClient

	for _, tc := range []struct {
		name string
		ac   AuthContext
		want v1alpha1.SubjectKind
	}{
		{"a carried User", AuthContext{"sub": kindsClientID, ClaimSubjectKind: "User"}, user},
		{"a carried Client", AuthContext{"sub": "alice", ClaimSubjectKind: "Client"}, cl},
		{"a carried unknown kind", AuthContext{"sub": "alice", ClaimSubjectKind: "ServiceAccount"}, "ServiceAccount"},
		{"a kind-less client_credentials token", AuthContext{"sub": "removed-client", "grant_type": GRANT_TYPE_CLIENT_CREDENTIALS}, cl},
		{"a kind-less context for a client", AuthContext{"sub": kindsClientID}, cl},
		{"a kind-less context for a user", AuthContext{"sub": "alice"}, user},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ex.ContextSubjectKind(tc.ac))
		})
	}

	var nilEx *Exchanger
	assert.Equal(t, user, nilEx.ContextSubjectKind(AuthContext{"sub": "alice"}), "nil-safe")
}
