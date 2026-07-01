package cache

import (
	"context"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

const minTTL = 1 * time.Millisecond

type Cache interface {
	Checksum() string
	Class() string
	Delete(ctx context.Context, key string) error
	Get(ctx context.Context, key string) (value string, exists bool, isCurrent bool, err error)
	// GetAndDelete atomically reads and removes the entry for key,
	// returning whether it existed. The primitive is needed to close
	// the concurrent-redeem race in auth-code / refresh-token rotation
	// (kdex-tech/host-manager#71): two concurrent callers that race on
	// the same key must observe exactly one winner (found=true) and
	// N-1 losers (found=false). Implementations that don't natively
	// expose an atomic GETDEL must guard with their own lock.
	GetAndDelete(ctx context.Context, key string) (value string, exists bool, isCurrent bool, err error)
	// DecrementIfPositive atomically decrements the integer value at key when
	// it exists and is > 0, returning the remaining count and ok=true. When the
	// key is missing or already <= 0 it returns (-1, false, nil) WITHOUT
	// writing — the fail-closed primitive behind bounded-use capability tokens.
	DecrementIfPositive(ctx context.Context, key string) (remaining int64, ok bool, err error)
	Host() string
	Set(ctx context.Context, key string, value string, opts ...SetOption) error
	TTL() time.Duration
	Uncycled() bool
}

type CacheOptions struct {
	MaxItems *int
	TTL      *time.Duration
	Uncycled bool
}

type SetOption func(*SetOptions)

type SetOptions struct {
	TTL *time.Duration
}

func WithTTL(ttl time.Duration) SetOption {
	return func(o *SetOptions) {
		o.TTL = &ttl
	}
}

type CacheManager interface {
	Cycle(checksum string, force bool) error
	GetCache(class string, opts CacheOptions) Cache
}

func NewCacheManager(addr, host string, ttl *time.Duration) (CacheManager, error) {
	if ttl == nil {
		ttl = new(24 * time.Hour)
	}

	if addr == "" {
		return &InMemoryCacheManager{
			caches:          make(map[string]Cache),
			currentChecksum: "0",
			host:            host,
			ttl:             *ttl,
		}, nil
	}

	client, err := valkey.NewClient(valkey.ClientOption{
		DisableCache: strings.Contains(addr, "127.0.0.1") || strings.Contains(addr, "localhost"),
		InitAddress:  []string{addr},
	})
	if err != nil {
		return nil, err
	}
	return &ValkeyCacheManager{
		caches:          make(map[string]Cache),
		client:          client,
		currentChecksum: "0",
		host:            host,
		ttl:             *ttl,
	}, nil
}
