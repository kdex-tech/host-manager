package cache

import (
	"context"
	"sync"
	"time"
)

type InMemoryCache struct {
	class           string
	currentChecksum string
	host            string
	mu              sync.RWMutex
	segments        map[string]map[string]memoryCacheEntry
	ttl             time.Duration
	uncycled        bool
	updateChan      chan time.Duration
}

var _ Cache = (*InMemoryCache)(nil)

func (c *InMemoryCache) Checksum() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentChecksum
}

func (c *InMemoryCache) Class() string {
	return c.class
}

func (c *InMemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, seg := range c.segments {
		delete(seg, key)
	}
	return nil
}

func (c *InMemoryCache) Host() string {
	return c.host
}

func (c *InMemoryCache) TTL() time.Duration {
	return c.ttl
}

func (c *InMemoryCache) Uncycled() bool {
	return c.uncycled
}

func (c *InMemoryCache) Get(ctx context.Context, key string) (string, bool, bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 1. Try Current Generation
	if seg, ok := c.segments[c.currentChecksum]; ok {
		if entry, found := seg[key]; found {
			// LAZY DELETION CHECK
			if time.Now().After(entry.expiry) {
				// Just pretend it's not found. The reaper will get it later.
				return "", false, true, nil
			}
			return entry.value, true, true, nil // Found in current version
		}
	}

	// 2. Try Previous Generation (Searching for any other segment)
	// In a two-generation system, there will only be one other key.
	for gen, seg := range c.segments {
		if gen == c.currentChecksum {
			continue
		}
		if entry, found := seg[key]; found {
			// LAZY DELETION CHECK
			if time.Now().After(entry.expiry) {
				// Just pretend it's not found. The reaper will get it later.
				return "", false, true, nil
			}
			return entry.value, true, false, nil // Found, but it's the old version
		}
	}

	return "", false, true, nil // Not found in either version
}

// Set stores a rendered page in the cache.
func (c *InMemoryCache) Set(ctx context.Context, key string, value string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.segments[c.currentChecksum] == nil {
		c.segments[c.currentChecksum] = make(map[string]memoryCacheEntry)
	}

	c.segments[c.currentChecksum][key] = memoryCacheEntry{
		expiry: time.Now().Add(c.ttl),
		value:  value,
	}
	return nil
}

func (c *InMemoryCache) reap() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for _, seg := range c.segments {
		for key, entry := range seg {
			if now.After(entry.expiry) {
				delete(seg, key)
			}
		}
	}
}

func (c *InMemoryCache) startReaper(interval time.Duration) {
	c.updateChan = make(chan time.Duration, 1)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.reap()

			case newInterval := <-c.updateChan:
				ticker.Reset(newInterval)
				c.reap()
			}
		}
	}()
}

type InMemoryCacheManager struct {
	caches          map[string]Cache
	currentChecksum string
	host            string
	mu              sync.RWMutex
	ttl             time.Duration
}

var _ CacheManager = (*InMemoryCacheManager)(nil)

func (m *InMemoryCacheManager) Cycle(checksum string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	oldChecksum := m.currentChecksum
	m.currentChecksum = checksum

	for _, cache := range m.caches {
		if mCache, ok := cache.(*InMemoryCache); ok {
			if mCache.uncycled && !force {
				continue
			}
			mCache.mu.Lock()
			mCache.currentChecksum = checksum

			// Ensure the new generation map exists
			if mCache.segments[checksum] == nil {
				mCache.segments[checksum] = make(map[string]memoryCacheEntry)
			}

			// If forced, wipe all generations except the current one
			if force {
				for g := range mCache.segments {
					if g != checksum {
						delete(mCache.segments, g)
					}
				}
			} else {
				// Standard cycle: delete anything older than the previous gen
				for g := range mCache.segments {
					if g != checksum && g != oldChecksum {
						delete(mCache.segments, g)
					}
				}
			}
			mCache.mu.Unlock()
		}
	}
	return nil
}

func (m *InMemoryCacheManager) GetCache(class string, opts CacheOptions) Cache {
	m.mu.RLock()
	cache, ok := m.caches[class]
	m.mu.RUnlock()

	if ok {
		mCache := cache.(*InMemoryCache)
		mCache.mu.Lock()
		mCache.uncycled = opts.Uncycled
		var newTTL *time.Duration
		if opts.TTL != nil && mCache.ttl != *opts.TTL && *opts.TTL >= minTTL {
			newTTL = opts.TTL
			mCache.ttl = *newTTL
		}
		mCache.mu.Unlock()
		// Send to channel AFTER unlocking the mutex
		if newTTL != nil {
			select {
			case mCache.updateChan <- *newTTL:
			default:
				// If channel is full, the reaper is already processing
				// or about to process an update.
			}
		}
		return cache
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	ttl := m.ttl
	if opts.TTL != nil && *opts.TTL >= minTTL {
		ttl = *opts.TTL
	}
	cache = &InMemoryCache{
		class:           class,
		currentChecksum: m.currentChecksum,
		host:            m.host,
		uncycled:        opts.Uncycled,
		segments:        make(map[string]map[string]memoryCacheEntry),
		ttl:             ttl,
	}
	go cache.(*InMemoryCache).startReaper(ttl)
	m.caches[class] = cache
	return cache
}

type memoryCacheEntry struct {
	expiry time.Time
	value  string
}
