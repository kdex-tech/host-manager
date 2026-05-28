package cache

import (
	"container/list"
	"context"
	"sync"
	"time"
)

type InMemoryCache struct {
	class           string
	currentChecksum string
	host            string
	lru             *list.List
	maxItems        int
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
		if entry, ok := seg[key]; ok {
			if entry.element != nil {
				c.lru.Remove(entry.element)
			}
			delete(seg, key)
		}
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
	c.mu.Lock()
	defer c.mu.Unlock()
	v, found, isCurrent := c.lookupLocked(key, false)
	return v, found, isCurrent, nil
}

// GetAndDelete atomically reads and removes the entry. Implementation:
// run the same Get walk and, on a hit, evict the entry before releasing
// the lock. The single c.mu.Lock around both halves is what makes this
// the contract-required single-winner primitive. See
// kdex-tech/host-manager#71.
func (c *InMemoryCache) GetAndDelete(ctx context.Context, key string) (string, bool, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, found, isCurrent := c.lookupLocked(key, true)
	return v, found, isCurrent, nil
}

// lookupLocked performs the two-generation key walk shared by Get and
// GetAndDelete. Caller must hold c.mu.Lock(). When evict is true, a
// found entry is removed from its segment + LRU before returning.
// In-memory lookup can't fail, so this returns no error — callers
// satisfy the cache.Cache interface by appending a nil err.
func (c *InMemoryCache) lookupLocked(key string, evict bool) (string, bool, bool) {
	// 1. Try Current Generation
	if seg, ok := c.segments[c.currentChecksum]; ok {
		if entry, found := seg[key]; found {
			// LAZY DELETION CHECK
			if time.Now().After(entry.expiry) {
				// Just pretend it's not found. The reaper will get it later.
				return "", false, true
			}
			if evict {
				if entry.element != nil {
					c.lru.Remove(entry.element)
				}
				delete(seg, key)
				return entry.value, true, true
			}
			if entry.element != nil {
				c.lru.MoveToFront(entry.element)
			}
			return entry.value, true, true // Found in current version
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
				return "", false, true
			}
			if evict {
				if entry.element != nil {
					c.lru.Remove(entry.element)
				}
				delete(seg, key)
				return entry.value, true, false
			}
			if entry.element != nil {
				c.lru.MoveToFront(entry.element)
			}
			return entry.value, true, false // Found, but it's the old version
		}
	}

	return "", false, true // Not found in either version
}

// Set stores a rendered page in the cache.
func (c *InMemoryCache) Set(ctx context.Context, key string, value string, opts ...SetOption) error {
	options := SetOptions{}
	for _, opt := range opts {
		opt(&options)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.segments[c.currentChecksum] == nil {
		c.segments[c.currentChecksum] = make(map[string]memoryCacheEntry)
	}

	ttl := c.ttl
	if options.TTL != nil {
		ttl = *options.TTL
	}

	// LRU logic
	if entry, found := c.segments[c.currentChecksum][key]; found {
		entry.value = value
		entry.expiry = time.Now().Add(ttl)
		if entry.element != nil {
			c.lru.MoveToFront(entry.element)
		}
		c.segments[c.currentChecksum][key] = entry
	} else {
		if c.maxItems > 0 && c.lru.Len() >= c.maxItems {
			// Evict LRU
			element := c.lru.Back()
			if element != nil {
				evictKey := element.Value.(string)
				c.lru.Remove(element)
				for _, seg := range c.segments {
					delete(seg, evictKey)
				}
			}
		}

		element := c.lru.PushFront(key)
		c.segments[c.currentChecksum][key] = memoryCacheEntry{
			element: element,
			expiry:  time.Now().Add(ttl),
			key:     key,
			value:   value,
		}
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
				if entry.element != nil {
					c.lru.Remove(entry.element)
				}
				delete(seg, key)
			}
		}
	}
}

// startReaper runs the cache's lazy-eviction loop. updateChan MUST be
// initialised by GetCache before this is spawned — see
// kdex-tech/host-manager#75. Pre-fix the channel was created inside
// this method, racing with the fast-path GetCache send.
func (c *InMemoryCache) startReaper(interval time.Duration) {
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
		if mCache.lru == nil {
			mCache.lru = list.New()
		}
		mCache.uncycled = opts.Uncycled
		if opts.MaxItems != nil {
			mCache.maxItems = *opts.MaxItems
		}
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

	if m.caches == nil {
		m.caches = make(map[string]Cache)
	}

	// Double-checked locking: another goroutine may have created the
	// cache between our RUnlock and Lock. Without this recheck, both
	// racers each construct a fresh InMemoryCache + reaper goroutine,
	// the second registration overwrites the first in m.caches[class],
	// and the loser's cache is orphaned (silent token loss + goroutine
	// leak). See kdex-tech/host-manager#57.
	if existing, ok := m.caches[class]; ok {
		return existing
	}

	ttl := m.ttl
	if opts.TTL != nil && *opts.TTL >= minTTL {
		ttl = *opts.TTL
	}
	maxItems := 1000
	if opts.MaxItems != nil {
		maxItems = *opts.MaxItems
	}
	cache = &InMemoryCache{
		class:           class,
		currentChecksum: m.currentChecksum,
		host:            m.host,
		lru:             list.New(),
		maxItems:        maxItems,
		uncycled:        opts.Uncycled,
		segments:        make(map[string]map[string]memoryCacheEntry),
		ttl:             ttl,
		// Initialise updateChan synchronously here so the fast-path
		// GetCache send (line ~266) can't race the reaper-goroutine
		// initialisation. See kdex-tech/host-manager#75.
		updateChan: make(chan time.Duration, 1),
	}
	m.caches[class] = cache
	go cache.(*InMemoryCache).startReaper(ttl)
	return cache
}

type memoryCacheEntry struct {
	element *list.Element
	expiry  time.Time
	key     string
	value   string
}
