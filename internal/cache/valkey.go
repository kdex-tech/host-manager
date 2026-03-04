package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
)

type ValkeyCache struct {
	client          valkey.Client
	class           string
	currentChecksum string
	host            string
	uncycled        bool
	mu              sync.RWMutex
	prefix          string // e.g. "{host:class:generation}:"
	prevPrefix      string // e.g. "{host:class:generation-1}:"
	ttl             time.Duration
}

var _ Cache = (*ValkeyCache)(nil)

func (s *ValkeyCache) Checksum() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentChecksum
}

func (s *ValkeyCache) Class() string {
	return s.class
}

func (s *ValkeyCache) Delete(ctx context.Context, key string) error {
	s.mu.RLock()
	curr := s.prefix
	prev := s.prevPrefix
	s.mu.RUnlock()

	// Delete current generation
	cmd := s.client.B().Del().Key(curr + key).Build()
	if err := s.client.Do(ctx, cmd).Error(); err != nil {
		return err
	}

	// Delete previous generation if it exists
	if prev != "" {
		cmd = s.client.B().Del().Key(prev + key).Build()
		return s.client.Do(ctx, cmd).Error()
	}

	return nil
}

func (s *ValkeyCache) Host() string {
	return s.host
}

func (s *ValkeyCache) TTL() time.Duration {
	return s.ttl
}

func (s *ValkeyCache) Uncycled() bool {
	return s.uncycled
}

func (s *ValkeyCache) Get(ctx context.Context, key string) (string, bool, bool, error) {
	s.mu.RLock()
	curr := s.prefix
	prev := s.prevPrefix
	s.mu.RUnlock()

	// 1. Try Current Generation
	val, found, err := s.getValue(ctx, curr+key)
	if err != nil || found {
		return val, found, true, err // Found in current version
	}

	// 2. Try Previous Generation
	if prev != "" {
		val, found, err := s.getValue(ctx, prev+key)
		if found {
			return val, true, false, err // Found, but it's the old version
		}
	}

	return "", false, true, nil // Not found in either version
}

func (s *ValkeyCache) Set(ctx context.Context, key string, value string) error {
	s.mu.RLock()
	prefix := s.prefix
	s.mu.RUnlock()
	cmd := s.client.B().Set().Key(prefix + key).Value(value).Px(s.ttl).Build()
	return s.client.Do(ctx, cmd).Error()
}

func (s *ValkeyCache) getValue(ctx context.Context, fullKey string) (string, bool, error) {
	cmd := s.client.B().Get().Key(fullKey).Build()
	val, err := s.client.Do(ctx, cmd).ToString()
	if valkey.IsValkeyNil(err) {
		return "", false, nil
	}
	return val, true, err
}

type ValkeyCacheManager struct {
	caches          map[string]Cache
	client          valkey.Client
	currentChecksum string
	host            string
	mu              sync.RWMutex
	ttl             time.Duration
}

var _ CacheManager = (*ValkeyCacheManager)(nil)

func (m *ValkeyCacheManager) Cycle(checksum string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentChecksum = checksum

	for _, cache := range m.caches {
		if vCache, ok := cache.(*ValkeyCache); ok {
			if vCache.uncycled && !force {
				continue
			}
			vCache.mu.Lock()
			if force {
				vCache.prevPrefix = ""
			} else {
				vCache.prevPrefix = vCache.prefix
			}
			vCache.currentChecksum = checksum
			vCache.prefix = fmt.Sprintf("{%s:%s:%s}:", m.host, vCache.class, checksum)
			vCache.mu.Unlock()
		}
	}
	return nil
}

func (m *ValkeyCacheManager) GetCache(class string, opts CacheOptions) Cache {
	m.mu.RLock()
	if cache, ok := m.caches[class]; ok {
		vCache := cache.(*ValkeyCache)
		vCache.mu.Lock()
		vCache.uncycled = opts.Uncycled
		if opts.TTL != nil && vCache.ttl != *opts.TTL && *opts.TTL >= minTTL {
			vCache.ttl = *opts.TTL
		}
		vCache.mu.Unlock()
		m.mu.RUnlock()
		return cache
	}
	m.mu.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	ttl := m.ttl
	// only accept TTLs greater than 5 second
	if opts.TTL != nil && *opts.TTL >= minTTL {
		ttl = *opts.TTL
	}
	cache := &ValkeyCache{
		client:          m.client,
		class:           class,
		currentChecksum: m.currentChecksum,
		host:            m.host,
		uncycled:        opts.Uncycled,
		prefix:          fmt.Sprintf("{%s:%s:%s}:", m.host, class, m.currentChecksum),
		ttl:             ttl,
	}
	m.caches[class] = cache
	return cache
}
