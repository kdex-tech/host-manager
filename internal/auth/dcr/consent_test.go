package dcr

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// countingCache counts the store's cache round trips.
type countingCache struct {
	cache.Cache
	gets, sets int
}

func (c *countingCache) Get(ctx context.Context, key string) (string, bool, bool, error) {
	c.gets++
	return c.Cache.Get(ctx, key)
}

func (c *countingCache) Set(ctx context.Context, key, value string, opts ...cache.SetOption) error {
	c.sets++
	return c.Cache.Set(ctx, key, value, opts...)
}

// Every covered authorize and every DCR refresh reads the record; only a
// stale grant may cost a second read (the re-load before the save) and a write.
func TestConsentFreshGrantCostsOneRead(t *testing.T) {
	const redirect = "https://a.example/cb"
	for name, read := range map[string]func(s *ConsentStore, ctx context.Context) (bool, error){
		"Covers": func(s *ConsentStore, ctx context.Context) (bool, error) {
			return s.Covers(ctx, "alice", "c1", redirect, nil)
		},
		"HasClient": func(s *ConsentStore, ctx context.Context) (bool, error) {
			return s.HasClient(ctx, "alice", "c1")
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, ctx := newConsentStore(t), context.Background()
			now := time.Unix(1_000_000, 0)
			s.now = func() time.Time { return now }
			require.NoError(t, s.Grant(ctx, "alice", "c1", redirect, nil))
			c := &countingCache{Cache: s.cache}
			s.cache = c

			now = now.Add(time.Hour)
			ok, err := read(s, ctx)
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, 1, c.gets, "a fresh grant is not re-loaded")
			assert.Equal(t, 0, c.sets)

			now = now.Add(25 * time.Hour)
			c.gets, c.sets = 0, 0
			ok, err = read(s, ctx)
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, 2, c.gets, "a stale grant is re-loaded before it is saved")
			assert.Equal(t, 1, c.sets)
		})
	}
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

// hookCache runs onFirstGet after the first Get has read its value, so a
// Revoke can land between a caller's load and its later save.
type hookCache struct {
	cache.Cache
	fired      bool
	onFirstGet func()
}

func (h *hookCache) Get(ctx context.Context, key string) (string, bool, bool, error) {
	val, ok, cur, err := h.Cache.Get(ctx, key)
	if !h.fired {
		h.fired = true
		h.onFirstGet()
	}
	return val, ok, cur, err
}

func TestConsentTouchDoesNotResurrectRevoked(t *testing.T) {
	const redirect = "https://a.example/cb"
	for name, read := range map[string]func(s *ConsentStore, ctx context.Context) (bool, error){
		"Covers": func(s *ConsentStore, ctx context.Context) (bool, error) {
			return s.Covers(ctx, "alice", "c1", redirect, nil)
		},
		"HasClient": func(s *ConsentStore, ctx context.Context) (bool, error) {
			return s.HasClient(ctx, "alice", "c1")
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, ctx := newConsentStore(t), context.Background()
			now := time.Unix(1_000_000, 0)
			s.now = func() time.Time { return now }
			require.NoError(t, s.Grant(ctx, "alice", "c1", redirect, nil))
			now = now.Add(25 * time.Hour) // the grant is stale, so the read will touch

			h := &hookCache{Cache: s.cache}
			h.onFirstGet = func() { require.NoError(t, s.Revoke(ctx, "alice", "c1", redirect)) }
			s.cache = h

			_, err := read(s, ctx) // may be true: it read before the revoke
			require.NoError(t, err)

			_, found, _, err := h.Cache.Get(ctx, consentKey("alice"))
			require.NoError(t, err)
			assert.False(t, found, "the revoked key is not re-created by the touch")
			ok, err := s.Covers(ctx, "alice", "c1", redirect, nil)
			require.NoError(t, err)
			assert.False(t, ok)
		})
	}
}

func TestConsentOverlongScopeIsNeverRecorded(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	long := strings.Repeat("x", MaxConsentScopeLen+1)
	require.NoError(t, s.Grant(ctx, "alice", "c1", "https://a.example/cb", []string{"openid", long}))
	ok, _ := s.Covers(ctx, "alice", "c1", "https://a.example/cb", []string{long})
	assert.False(t, ok)
	ok, _ = s.Covers(ctx, "alice", "c1", "https://a.example/cb", []string{"openid"})
	assert.True(t, ok)
}

func TestConsentEvictionKeepsTheJustGranted(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	s.now = func() time.Time { return time.Unix(1_000_000, 0) }
	last := ""
	for i := 0; i <= MaxConsentClients; i++ {
		last = fmt.Sprintf("c%03d", i)
		require.NoError(t, s.Grant(ctx, "alice", last, "https://a.example/cb", nil))
	}
	ok, _ := s.Covers(ctx, "alice", last, "https://a.example/cb", nil)
	assert.True(t, ok, "last-granted client survives same-second ties")

	for i := 0; i <= MaxConsentRedirects; i++ {
		last = fmt.Sprintf("https://r%d.example/cb", i)
		require.NoError(t, s.Grant(ctx, "bob", "c1", last, nil))
	}
	ok, _ = s.Covers(ctx, "bob", "c1", last, nil)
	assert.True(t, ok, "last-granted redirect survives same-second ties")
}

func TestConsentCorruptRecordReadsAsNotCovered(t *testing.T) {
	s, ctx := newConsentStore(t), context.Background()
	require.NoError(t, s.cache.Set(ctx, consentKey("alice"), "not json"))
	ok, err := s.Covers(ctx, "alice", "c1", "https://a.example/cb", nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

type failingCache struct{ cache.Cache }

func (failingCache) Get(context.Context, string) (string, bool, bool, error) {
	return "", false, false, errors.New("boom")
}

func TestConsentCoversPropagatesCacheError(t *testing.T) {
	s := newConsentStore(t)
	s.cache = failingCache{s.cache}
	ok, err := s.Covers(context.Background(), "alice", "c1", "https://a.example/cb", nil)
	assert.False(t, ok)
	assert.Error(t, err)
}
