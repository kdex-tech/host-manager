package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"kdex.dev/crds/api/v1alpha1"
)

func registryClients(ids ...string) map[string]AuthClient {
	m := map[string]AuthClient{}
	for _, id := range ids {
		m[id] = AuthClient{ClientID: id}
	}
	return m
}

func newRegistryExchanger(t *testing.T, cm cache.CacheManager, ids ...string) (*Exchanger, error) {
	t.Helper()
	return NewExchanger(context.Background(), Config{Clients: registryClients(ids...)}, cm, nil, nil)
}

// atRegistryTime runs the registry's clock at unix second sec until the test
// ends or the next call.
func atRegistryTime(t *testing.T, sec int64) {
	t.Helper()
	prev := clientRegistryNow
	clientRegistryNow = func() time.Time { return time.Unix(sec, 0) }
	t.Cleanup(func() { clientRegistryNow = prev })
}

// buildAt builds an Exchanger configuring ids, with the registry's clock at
// unix second sec.
func buildAt(t *testing.T, cm cache.CacheManager, sec int64, ids ...string) *Exchanger {
	t.Helper()
	atRegistryTime(t, sec)
	ex, err := newRegistryExchanger(t, cm, ids...)
	require.NoError(t, err)
	return ex
}

func present() clientRecord { return clientRecord{Present: true} }

func TestClientRegistry_MergesAcrossBuilds(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-merge", nil)
	require.NoError(t, err)

	first := buildAt(t, cm, 100, "a", "b")
	assert.Equal(t, map[string]clientRecord{"a": present(), "b": present()}, first.clientRegistry)

	second := buildAt(t, cm, 200, "b", "c")
	assert.Equal(t, map[string]clientRecord{
		"a": {Present: false, RemovedAt: 200},
		"b": present(),
		"c": present(),
	}, second.clientRegistry)
}

// TestClientRegistry_RecordFormat pins the stored value (A2: the runbook
// describes this shape): an object of per-id records, keys sorted.
func TestClientRegistry_RecordFormat(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-format", nil)
	require.NoError(t, err)
	buildAt(t, cm, 100, "b", "a")
	buildAt(t, cm, 200, "b")

	store := cm.GetCache(clientRegistryClass, cache.CacheOptions{MaxItems: new(0), Uncycled: true})
	v, found, _, err := store.Get(context.Background(), clientRegistryKey)
	require.NoError(t, err)
	require.True(t, found)
	assert.JSONEq(t, `{"a":{"present":false,"removedAt":200},"b":{"present":true,"removedAt":0}}`, v)
	assert.Equal(t, `{"a":{"present":false,"removedAt":200},"b":{"present":true,"removedAt":0}}`, v,
		"written with sorted keys")
}

// TestClientRegistry_ReaddKeepsTheCutoff (A1, a user decision): re-adding a
// client stamps its cutoff again (Ruling Q3), and each later removal or
// re-add moves it forward.
func TestClientRegistry_ReaddKeepsTheCutoff(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-readd", nil)
	require.NoError(t, err)

	buildAt(t, cm, 100, "a")
	ex := buildAt(t, cm, 200)
	assert.Equal(t, clientRecord{Present: false, RemovedAt: 200}, ex.clientRegistry["a"], "removed")
	ex = buildAt(t, cm, 300, "a")
	assert.Equal(t, clientRecord{Present: true, RemovedAt: 300}, ex.clientRegistry["a"],
		"re-added: the cutoff moves to the re-add (Q3)")
	ex = buildAt(t, cm, 350, "a")
	assert.Equal(t, clientRecord{Present: true, RemovedAt: 300}, ex.clientRegistry["a"],
		"still configured: the cutoff stays")
	ex = buildAt(t, cm, 400)
	assert.Equal(t, clientRecord{Present: false, RemovedAt: 400}, ex.clientRegistry["a"], "removed again")
	ex = buildAt(t, cm, 500, "a")
	assert.Equal(t, clientRecord{Present: true, RemovedAt: 500}, ex.clientRegistry["a"], "re-added again")
	ex = buildAt(t, cm, 600)
	assert.Equal(t, clientRecord{Present: false, RemovedAt: 600}, ex.clientRegistry["a"])
	ex = buildAt(t, cm, 700)
	assert.Equal(t, clientRecord{Present: false, RemovedAt: 600}, ex.clientRegistry["a"],
		"an id already absent stays as it is")
	ex = buildAt(t, cm, 800, "a")
	assert.Equal(t, clientRecord{Present: true, RemovedAt: 800}, ex.clientRegistry["a"])
}

// A peer whose clock runs ahead recorded a later removal; a build with an
// earlier clock does not move it back.
func TestClientRegistry_RemovalNeverMovesBack(t *testing.T) {
	m := mergeClientRegistry(map[string]clientRecord{"a": {Present: true, RemovedAt: 500}}, nil, 300)
	assert.Equal(t, clientRecord{Present: false, RemovedAt: 500}, m.registry["a"])
}

func TestClientRegistry_RemovedClientStillNamesClient(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-removed", nil)
	require.NoError(t, err)
	_, err = newRegistryExchanger(t, cm, "a", "b")
	require.NoError(t, err)
	ex, err := newRegistryExchanger(t, cm, "b", "c")
	require.NoError(t, err)

	assert.True(t, ex.NamesClient("a"))
	assert.False(t, ex.IsConfiguredClient("a"))
	assert.Equal(t, v1alpha1.SubjectKindClient, ex.SubjectKindOf("a"))
	assert.False(t, ex.NamesClient("alice"))

	_, err = ex.userBindingSubject(jwt.MapClaims{"sub": "a"}, "a", "test")
	assert.ErrorIs(t, err, ErrSubjectNamesClient)
}

// Concurrent builds lose nothing: every id any of them configured has a
// record afterwards, present or removed.
func TestClientRegistry_ConcurrentBuildsLoseNothing(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-concurrent", nil)
	require.NoError(t, err)

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = loadClientRegistry(context.Background(), cm, registryClients(fmt.Sprintf("c%d", i)))
		}()
	}
	wg.Wait()
	for _, e := range errs {
		require.NoError(t, e)
	}

	final, err := loadClientRegistry(context.Background(), cm, nil)
	require.NoError(t, err)
	for i := range n {
		assert.Contains(t, final, fmt.Sprintf("c%d", i))
	}
}

// countingRegistryCache counts the registry's reads and updates, and can
// evict the key right after an Update writes it.
type countingRegistryCache struct {
	cache.Cache
	mu              sync.Mutex
	gets, updates   int
	evictAfterWrite bool
}

func (c *countingRegistryCache) Get(ctx context.Context, key string) (string, bool, bool, error) {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	return c.Cache.Get(ctx, key)
}

func (c *countingRegistryCache) Update(ctx context.Context, key string, fn cache.UpdateFunc, opts ...cache.SetOption) (bool, error) {
	c.mu.Lock()
	c.updates++
	c.mu.Unlock()
	wrote, err := c.Cache.Update(ctx, key, fn, opts...)
	if err == nil && wrote && c.evictAfterWrite {
		_ = c.Delete(ctx, key)
	}
	return wrote, err
}

// registryManager hands out one wrapped client-registry cache, so the rest
// of NewExchanger behaves normally.
type registryManager struct {
	cache.CacheManager
	wrap func(cache.Cache) cache.Cache
}

func (m registryManager) GetCache(class string, opts cache.CacheOptions) cache.Cache {
	c := m.CacheManager.GetCache(class, opts)
	if class == clientRegistryClass {
		return m.wrap(c)
	}
	return c
}

func newCountingRegistry(t *testing.T, name string) (registryManager, *countingRegistryCache) {
	t.Helper()
	base, err := cache.NewCacheManager("", name, nil)
	require.NoError(t, err)
	counting := &countingRegistryCache{Cache: base.GetCache(clientRegistryClass, cache.CacheOptions{MaxItems: new(0), Uncycled: true})}
	return registryManager{CacheManager: base, wrap: func(cache.Cache) cache.Cache { return counting }}, counting
}

// TestClientRegistry_UnchangedConfigWritesNothing (A4): a build whose
// configuration the registry already reflects costs one Get and no Update.
func TestClientRegistry_UnchangedConfigWritesNothing(t *testing.T) {
	cm, counting := newCountingRegistry(t, "registry-fastpath")
	buildAt(t, cm, 100, "a", "b")
	assert.Equal(t, 1, counting.updates, "the first build records its ids")

	counting.gets, counting.updates = 0, 0
	ex := buildAt(t, cm, 200, "a", "b")
	assert.Equal(t, 1, counting.gets)
	assert.Equal(t, 0, counting.updates, "an unchanged config wrote")
	assert.Equal(t, map[string]clientRecord{"a": present(), "b": present()}, ex.clientRegistry)
}

// TestClientRegistry_NoSecondRead (A4): the registry a build uses is the one
// its own merge computed. Re-reading the key afterwards could see it evicted
// and answer with a partial registry.
func TestClientRegistry_NoSecondRead(t *testing.T) {
	cm, counting := newCountingRegistry(t, "registry-noreread")
	buildAt(t, cm, 100, "a")
	counting.evictAfterWrite = true
	counting.gets = 0

	ex := buildAt(t, cm, 200, "b")
	assert.Equal(t, 1, counting.gets, "one fast-path read, none after the Update")
	assert.Equal(t, map[string]clientRecord{"a": {RemovedAt: 200}, "b": present()}, ex.clientRegistry,
		"the merge's own result, eviction or not")
}

// hangingRegistryCache blocks every call until its context is done.
type hangingRegistryCache struct{ cache.Cache }

func (hangingRegistryCache) Get(ctx context.Context, _ string) (string, bool, bool, error) {
	<-ctx.Done()
	return "", false, false, ctx.Err()
}

// TestClientRegistry_HasADeadline (A4): a hung store fails the build at the
// registry's deadline instead of wedging the reconcile.
func TestClientRegistry_HasADeadline(t *testing.T) {
	prev := clientRegistryTimeout
	clientRegistryTimeout = 50 * time.Millisecond
	t.Cleanup(func() { clientRegistryTimeout = prev })
	base, err := cache.NewCacheManager("", "registry-deadline", nil)
	require.NoError(t, err)
	cm := registryManager{CacheManager: base, wrap: func(c cache.Cache) cache.Cache { return hangingRegistryCache{c} }}

	start := time.Now()
	_, err = newRegistryExchanger(t, cm, "a")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)
}

// failingRegistryCache fails Update, standing in for an unreachable store.
type failingRegistryCache struct{ cache.Cache }

func (failingRegistryCache) Update(context.Context, string, cache.UpdateFunc, ...cache.SetOption) (bool, error) {
	return false, errors.New("store unavailable")
}

func TestNewExchanger_RegistryFailureFails(t *testing.T) {
	base, err := cache.NewCacheManager("", "registry-failure", nil)
	require.NoError(t, err)
	cm := registryManager{CacheManager: base, wrap: func(c cache.Cache) cache.Cache { return failingRegistryCache{c} }}

	ex, err := newRegistryExchanger(t, cm, "a")
	require.ErrorContains(t, err, "client registry")
	assert.Nil(t, ex)
}

func TestClientRegistry_SkipsDCR(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-dcr", nil)
	require.NoError(t, err)

	got, err := loadClientRegistry(context.Background(), cm, registryClients("a", "dcr_x"))
	require.NoError(t, err)
	assert.Contains(t, got, "a")
	assert.NotContains(t, got, "dcr_x")

	stored, err := loadClientRegistry(context.Background(), cm, nil)
	require.NoError(t, err)
	assert.NotContains(t, stored, "dcr_x")

	ex, err := newRegistryExchanger(t, cm, "a")
	require.NoError(t, err)
	assert.True(t, ex.NamesClient("dcr_x"))
}

// A nil TTL falls back to the manager default, so a registry that took it
// would vanish and rebuild from current config, forgetting removed clients.
func TestClientRegistry_SurvivesManagerTTL(t *testing.T) {
	ttl := 50 * time.Millisecond
	cm, err := cache.NewCacheManager("", "registry-ttl", &ttl)
	require.NoError(t, err)

	_, err = newRegistryExchanger(t, cm, "a")
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond)
	ex, err := newRegistryExchanger(t, cm, "b")
	require.NoError(t, err)

	assert.True(t, ex.NamesClient("a"), "a removed client outlives the manager TTL")
}

func seedRegistry(t *testing.T, cm cache.CacheManager, value string) cache.Cache {
	t.Helper()
	store := cm.GetCache(clientRegistryClass, cache.CacheOptions{MaxItems: new(0), Uncycled: true})
	require.NoError(t, store.Set(context.Background(), clientRegistryKey, value, cache.WithoutExpiry()))
	return store
}

// A corrupt stored value must fail the build and stay as it was: replacing it
// with a partial registry would forget every removed client. The registry
// never shipped in another shape, so an array of ids (the pre-quad shape) is
// corrupt too. The error names the full key, so an operator can find it
// (A5).
func TestClientRegistry_CorruptValueFailsClosed(t *testing.T) {
	for name, value := range map[string]string{
		"not json":                   "not json",
		"the array shape":            `["a","b"]`,
		"null":                       `null`,
		"a null record":              `{"a":null}`,
		"an unknown field":           `{"a":{"present":true,"removedAt":0,"extra":1}}`,
		"a negative removedAt":       `{"a":{"present":false,"removedAt":-1}}`,
		"a record of the wrong type": `{"a":true}`,
		"trailing data":              `{} {}`,
		"a trailing brace":           `{"a":{"present":true,"removedAt":0}}}`,
		"a trailing bracket":         `{"a":{"present":true,"removedAt":0}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			cm, err := cache.NewCacheManager("", "registry-corrupt", nil)
			require.NoError(t, err)
			store := seedRegistry(t, cm, value)

			ex, err := newRegistryExchanger(t, cm, "a")
			require.ErrorContains(t, err, "client registry")
			require.ErrorContains(t, err, "{<host>:client-registry:0}:ids", "the error names the full key")
			assert.Nil(t, ex)

			v, _, _, _ := store.Get(context.Background(), clientRegistryKey)
			assert.Equal(t, value, v)
		})
	}
}

type failingGetCache struct{ cache.Cache }

func (failingGetCache) Get(context.Context, string) (string, bool, bool, error) {
	return "", false, false, errors.New("read failed")
}

func TestClientRegistry_ReadFailureFails(t *testing.T) {
	base, err := cache.NewCacheManager("", "registry-getfail", nil)
	require.NoError(t, err)
	cm := registryManager{CacheManager: base, wrap: func(c cache.Cache) cache.Cache { return failingGetCache{c} }}
	_, err = newRegistryExchanger(t, cm, "a")
	require.ErrorContains(t, err, "client registry")
	require.ErrorContains(t, err, "{<host>:client-registry:0}:ids")
}

// TestClientRegistry_LogsReservations (A2): each id newly recorded, and each
// newly marked removed, is logged at V(0), naming the id (operator config,
// not a user's identity). An unchanged build logs nothing.
func TestClientRegistry_LogsReservations(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-logs", nil)
	require.NoError(t, err)
	var buf strings.Builder
	var mu sync.Mutex
	ctx := logr.NewContext(context.Background(), funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		buf.WriteString(prefix + " " + args + "\n")
	}, funcr.Options{Verbosity: 0}))
	take := func() string {
		mu.Lock()
		defer mu.Unlock()
		s := buf.String()
		buf.Reset()
		return s
	}

	atRegistryTime(t, 100)
	_, err = loadClientRegistry(ctx, cm, registryClients("a", "b"))
	require.NoError(t, err)
	out := take()
	assert.Equal(t, 2, strings.Count(out, "recorded a configured client id"), out)
	assert.Contains(t, out, `"client_id"="a"`)
	assert.Contains(t, out, `"client_id"="b"`)

	_, err = loadClientRegistry(ctx, cm, registryClients("a", "b"))
	require.NoError(t, err)
	assert.Empty(t, take(), "an unchanged build logged")

	atRegistryTime(t, 200)
	_, err = loadClientRegistry(ctx, cm, registryClients("a"))
	require.NoError(t, err)
	out = take()
	assert.Equal(t, 1, strings.Count(out, "marked a client id removed"), out)
	assert.Contains(t, out, `"client_id"="b"`)
	assert.Contains(t, out, `"removed_at"=200`)

	atRegistryTime(t, 300)
	_, err = loadClientRegistry(ctx, cm, registryClients("a", "b"))
	require.NoError(t, err)
	out = take()
	assert.Equal(t, 1, strings.Count(out, "client re-added; credentials issued before now are refused"), out)
	assert.Contains(t, out, `"client_id"="b"`)
	assert.Contains(t, out, `"removed_at"=300`, "the line names the cutoff")
	assert.NotContains(t, out, "recorded a configured client id", "a re-add is not a new record")
}

// TestNewExchanger_FailedBuildReservesNothing (quad 2026-10-28, A3): a
// config whose Exchanger never builds never takes effect, so it must not
// reserve its client ids. The OIDC provider here is down, which fails the
// build after the registry merge used to run.
func TestNewExchanger_FailedBuildReservesNothing(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-failed-build", nil)
	require.NoError(t, err)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(idp.Close)

	cfg := Config{Clients: registryClients("never-took-effect")}
	cfg.OIDC.ProviderURL = idp.URL
	ex, err := NewExchanger(context.Background(), cfg, cm, nil, nil)
	require.ErrorContains(t, err, "OIDC provider")
	require.Nil(t, ex)

	ex, err = newRegistryExchanger(t, cm, "a")
	require.NoError(t, err)
	assert.False(t, ex.NamesClient("never-took-effect"), "a build that failed reserved its client id")
}
