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
