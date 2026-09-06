package auth

import (
	"context"
	"testing"

	"github.com/kdex-tech/host-manager/internal/cache"
	"github.com/stretchr/testify/require"
)

func newGenTestExchanger(t *testing.T) *Exchanger {
	t.Helper()
	cm, err := cache.NewCacheManager("", "grant-gen-test", nil)
	require.NoError(t, err)
	ex, err := NewExchanger(context.Background(), Config{}, cm, autoExtendStubIdentityProvider{})
	require.NoError(t, err)
	return ex
}

func TestGrantGenerationRoundTrip(t *testing.T) {
	ex := newGenTestExchanger(t)
	ctx := context.Background()

	// Absent generation is the empty sentinel.
	require.Equal(t, "", ex.grantGeneration(ctx))

	ex.BumpGrantGeneration(ctx)
	first := ex.grantGeneration(ctx)
	require.NotEqual(t, "", first)

	// A nil exchanger / nil cache must be safe and return the sentinel.
	var nilEx *Exchanger
	require.Equal(t, "", nilEx.grantGeneration(ctx))
	nilEx.BumpGrantGeneration(ctx) // must not panic
}
