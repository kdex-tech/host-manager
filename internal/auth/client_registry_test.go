package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

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

func TestClientRegistry_MergesAcrossBuilds(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-merge", nil)
	require.NoError(t, err)

	first, err := newRegistryExchanger(t, cm, "a", "b")
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"a": {}, "b": {}}, first.formerClients)

	second, err := newRegistryExchanger(t, cm, "b", "c")
	require.NoError(t, err)
	assert.Equal(t, map[string]struct{}{"a": {}, "b": {}, "c": {}}, second.formerClients)
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

	_, err = ex.userBindingKey(jwt.MapClaims{"sub": "a"}, "a", "test")
	assert.ErrorIs(t, err, ErrSubjectNamesClient)
}

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

// failingRegistryCache fails Update, standing in for an unreachable store.
type failingRegistryCache struct{ cache.Cache }

func (failingRegistryCache) Update(context.Context, string, cache.UpdateFunc, ...cache.SetOption) (bool, error) {
	return false, errors.New("store unavailable")
}

// registryFailingManager fails only the client-registry class, so the rest of
// NewExchanger behaves normally.
type registryFailingManager struct{ cache.CacheManager }

func (m registryFailingManager) GetCache(class string, opts cache.CacheOptions) cache.Cache {
	c := m.CacheManager.GetCache(class, opts)
	if class == clientRegistryClass {
		return failingRegistryCache{c}
	}
	return c
}

func TestNewExchanger_RegistryFailureFails(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-failure", nil)
	require.NoError(t, err)

	ex, err := newRegistryExchanger(t, registryFailingManager{cm}, "a")
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
// with a partial registry would forget every removed client.
func TestClientRegistry_CorruptValueFailsClosed(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-corrupt", nil)
	require.NoError(t, err)
	store := seedRegistry(t, cm, "not json")

	ex, err := newRegistryExchanger(t, cm, "a")
	require.ErrorContains(t, err, "client registry")
	assert.Nil(t, ex)

	v, _, _, _ := store.Get(context.Background(), clientRegistryKey)
	assert.Equal(t, "not json", v)
}

type failingGetCache struct{ cache.Cache }

func (failingGetCache) Get(context.Context, string) (string, bool, bool, error) {
	return "", false, false, errors.New("read failed")
}

type getFailingManager struct{ cache.CacheManager }

func (m getFailingManager) GetCache(class string, opts cache.CacheOptions) cache.Cache {
	c := m.CacheManager.GetCache(class, opts)
	if class == clientRegistryClass {
		return failingGetCache{c}
	}
	return c
}

func TestClientRegistry_ReadFailureFails(t *testing.T) {
	cm, err := cache.NewCacheManager("", "registry-getfail", nil)
	require.NoError(t, err)
	_, err = newRegistryExchanger(t, getFailingManager{cm}, "a")
	require.ErrorContains(t, err, "client registry")
}
