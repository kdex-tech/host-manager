package dcr

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newConsentStore(t *testing.T) *ConsentStore {
	t.Helper()
	ttl := time.Hour
	cm, err := cache.NewCacheManager("", "consent-test", &ttl)
	require.NoError(t, err)
	return NewConsentStore(cm, ttl, 10000)
}

func TestConsentCoversOnlyTheRedirectAndScopesAllowed(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", []string{"openid", "email"}))

	ok, err := s.Covers(ctx, "alice", "c1", "https://a.example/cb", []string{"email"})
	require.NoError(t, err)
	assert.True(t, ok, "subset of granted scopes")

	ok, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	assert.True(t, ok, "empty request is covered by any record for the redirect")

	ok, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", []string{"roles"})
	assert.False(t, ok, "broader scope")

	ok, _ = s.Covers(ctx, "alice", "c1", "https://b.example/cb", nil)
	assert.False(t, ok, "another redirect of the same client")

	ok, _ = s.Covers(ctx, "bob", "c1", "https://a.example/cb", nil)
	assert.False(t, ok, "another subject")
}

func TestConsentGrantUnionsAndRevokeRemoves(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", []string{"openid"}))
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", []string{"email"}))
	ok, _ := s.Covers(ctx, "alice", "c1", "https://a.example/cb", []string{"openid", "email"})
	assert.True(t, ok)

	has, err := s.HasClient(ctx, "alice", "c1")
	require.NoError(t, err)
	assert.True(t, has)

	require.NoError(t, s.Revoke(ctx, "alice", "c1", "https://a.example/cb"))
	ok, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	assert.False(t, ok)
	has, _ = s.HasClient(ctx, "alice", "c1")
	assert.False(t, has)
}

func TestConsentRecordIsBounded(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }

	for i := 0; i < MaxConsentClients+5; i++ {
		now = now.Add(time.Minute)
		require.NoError(t, s.Grant(ctx, "alice", fmt.Sprintf("c%03d", i), "https://a.example/cb", nil))
	}
	ok, _ := s.Covers(ctx, "alice", "c000", "https://a.example/cb", nil)
	assert.False(t, ok, "the oldest client was evicted")
	ok, _ = s.Covers(ctx, "alice", fmt.Sprintf("c%03d", MaxConsentClients+4), "https://a.example/cb", nil)
	assert.True(t, ok)

	for i := 0; i < MaxConsentRedirects+2; i++ {
		now = now.Add(time.Minute)
		require.NoError(t, s.Grant(ctx, "bob", "c1", fmt.Sprintf("https://r%d.example/cb", i), nil))
	}
	ok, _ = s.Covers(ctx, "bob", "c1", "https://r0.example/cb", nil)
	assert.False(t, ok, "the oldest redirect was evicted")

	long := make([]string, 0, MaxConsentScopes+10)
	for i := 0; i < MaxConsentScopes+10; i++ {
		long = append(long, fmt.Sprintf("s%d", i))
	}
	require.NoError(t, s.Grant(ctx, "carol", "c1", "https://a.example/cb", long))
	rec, err := s.load(ctx, "carol")
	require.NoError(t, err)
	assert.LessOrEqual(t, len(rec.Clients["c1"]["https://a.example/cb"].Scopes), MaxConsentScopes)
}

func TestConsentTouchWritesAtMostDaily(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", nil))

	now = now.Add(time.Hour)
	_, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	rec, _ := s.load(ctx, "alice")
	assert.Equal(t, time.Unix(1_000_000, 0).Unix(), rec.Clients["c1"]["https://a.example/cb"].Touched, "not stale yet")

	now = now.Add(25 * time.Hour)
	_, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	rec, _ = s.load(ctx, "alice")
	assert.Equal(t, now.Unix(), rec.Clients["c1"]["https://a.example/cb"].Touched)
}

func TestConsentRevokeLastDeletesTheKey(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", nil))
	_, found, _, err := s.cache.Get(ctx, consentKey("alice"))
	require.NoError(t, err)
	require.True(t, found)

	require.NoError(t, s.Revoke(ctx, "alice", "c1", "https://a.example/cb"))
	_, found, _, err = s.cache.Get(ctx, consentKey("alice"))
	require.NoError(t, err)
	assert.False(t, found, "no empty record is stored")
}
