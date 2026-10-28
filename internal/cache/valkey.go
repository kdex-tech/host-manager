package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/valkey-io/valkey-go"
)

type ValkeyCache struct {
	client          valkey.Client
	class           string
	currentChecksum string
	host            string
	maxItems        int
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

// GetAndDelete atomically reads and removes the entry. Backed by
// Valkey's GETDEL primitive (single round-trip, server-side atomic),
// so two concurrent callers racing on the same key always produce
// exactly one winner. See kdex-tech/host-manager#71.
func (s *ValkeyCache) GetAndDelete(ctx context.Context, key string) (string, bool, bool, error) {
	s.mu.RLock()
	curr := s.prefix
	prev := s.prevPrefix
	s.mu.RUnlock()

	val, found, err := s.getDelValue(ctx, curr+key)
	if err != nil || found {
		return val, found, true, err
	}

	if prev != "" {
		val, found, err := s.getDelValue(ctx, prev+key)
		if found {
			return val, true, false, err
		}
	}

	return "", false, true, nil
}

func (s *ValkeyCache) getDelValue(ctx context.Context, fullKey string) (string, bool, error) {
	cmd := s.client.B().Getdel().Key(fullKey).Build()
	val, err := s.client.Do(ctx, cmd).ToString()
	if valkey.IsValkeyNil(err) {
		return "", false, nil
	}
	return val, true, err
}

// decrIfPositiveScript is the fail-closed atomic decrement behind
// DecrementIfPositive. A single EVAL avoids the TOCTOU that a
// GET-then-DECR round trip would have under concurrent callers. Returns
// the remaining count (>=0) after a successful decrement, or -1 when the
// key is missing or its value is non-integer or already <= 0.
const decrIfPositiveScript = `
local v = redis.call('GET', KEYS[1])
if not v then return -1 end
local n = tonumber(v)
if not n or n <= 0 then return -1 end
redis.call('DECR', KEYS[1])
return n - 1`

// DecrementIfPositive atomically decrements the integer value at key when
// it exists and is > 0, returning the remaining count and ok=true;
// otherwise it fails closed with (-1, false, nil) WITHOUT writing. This
// is the bounded-use capability token primitive; callers create these
// caches with CacheOptions{Uncycled: true}, so — unlike Get/Set — there
// is no prevPrefix fallback to consider.
func (s *ValkeyCache) DecrementIfPositive(ctx context.Context, key string) (int64, bool, error) {
	s.mu.RLock()
	prefix := s.prefix
	s.mu.RUnlock()

	cmd := s.client.B().Eval().Script(decrIfPositiveScript).Numkeys(1).Key(prefix + key).Build()
	rem, err := s.client.Do(ctx, cmd).ToInt64()
	if err != nil {
		return -1, false, err
	}
	if rem < 0 {
		return -1, false, nil
	}
	return rem, true, nil
}

func (s *ValkeyCache) Set(ctx context.Context, key string, value string, opts ...SetOption) error {
	prefix, ttl, noExpiry := s.target(opts)
	return s.client.Do(ctx, s.setCmd(prefix+key, value, ttl, noExpiry)).Error()
}

// updateAttempts bounds Update's optimistic retries under contention.
const updateAttempts = 16

// errUpdateContended is Update's answer when every attempt lost a race.
var errUpdateContended = errors.New("cache update: key kept changing under contention")

// Update is an optimistic transaction: WATCH the key, read it, and write the
// new value in a MULTI/EXEC that Valkey aborts if anyone wrote the key since
// the WATCH; an aborted attempt runs fn again on the newer value.
func (s *ValkeyCache) Update(ctx context.Context, key string, fn UpdateFunc, opts ...SetOption) (bool, error) {
	prefix, ttl, noExpiry := s.target(opts)
	fullKey := prefix + key

	var wrote bool
	err := s.client.Dedicated(func(c valkey.DedicatedClient) error {
		// A failure between WATCH and EXEC must not hand the pooled
		// connection back still watching, or its next user's EXEC aborts.
		unwatch := func(cause error) error {
			return errors.Join(cause, c.Do(ctx, c.B().Unwatch().Build()).Error())
		}
		for range updateAttempts {
			if err := c.Do(ctx, c.B().Watch().Key(fullKey).Build()).Error(); err != nil {
				return unwatch(err)
			}
			current, err := c.Do(ctx, c.B().Get().Key(fullKey).Build()).ToString()
			found := err == nil
			if err != nil && !valkey.IsValkeyNil(err) {
				return unwatch(err)
			}
			next, write := fn(current, found)
			if !write {
				return unwatch(nil)
			}
			replies := c.DoMulti(ctx,
				c.B().Multi().Build(),
				s.setCmd(fullKey, next, ttl, noExpiry),
				c.B().Exec().Build())
			exec := replies[len(replies)-1]
			if _, err := exec.ToArray(); valkey.IsValkeyNil(err) {
				continue // a concurrent write aborted the transaction
			} else if err != nil {
				return unwatch(err) // EXEC never ran: still watching
			}
			wrote = true
			return nil
		}
		return errUpdateContended
	})
	return wrote, err
}

// target is the prefix, ttl and no-expiry flag a write with opts goes to.
func (s *ValkeyCache) target(opts []SetOption) (string, time.Duration, bool) {
	options := applySetOptions(opts)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if options.TTL != nil {
		return s.prefix, *options.TTL, options.NoExpiry
	}
	return s.prefix, s.ttl, options.NoExpiry
}

// setCmd is the SET for a write: with PX ttl, or with no expiry at all.
func (s *ValkeyCache) setCmd(fullKey, value string, ttl time.Duration, noExpiry bool) valkey.Completed {
	set := s.client.B().Set().Key(fullKey).Value(value)
	if noExpiry {
		return set.Build()
	}
	return set.Px(ttl).Build()
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
			vCache.mu.Lock()
			switch {
			case vCache.uncycled:
				// The surviving scope has one generation.
			case force:
				vCache.prevPrefix = ""
				vCache.currentChecksum = checksum
				vCache.prefix = m.prefix(vCache.class, checksum)
			case vCache.currentChecksum != checksum:
				// Only a new generation spends the previous one's grace
				// window; a reconcile that changed nothing keeps it.
				vCache.prevPrefix = vCache.prefix
				vCache.currentChecksum = checksum
				vCache.prefix = m.prefix(vCache.class, checksum)
			}
			vCache.mu.Unlock()
		}
	}
	return nil
}

func (m *ValkeyCacheManager) prefix(class, generation string) string {
	return fmt.Sprintf("{%s:%s:%s}:", m.host, class, generation)
}

// ScanGenerations walks the keyspace with SCAN, so it costs a pass over every
// key in the store; it is meant for a one-time recovery, not a request path.
func (m *ValkeyCacheManager) ScanGenerations(ctx context.Context, class string, fn func(Entry) error) error {
	pattern := globEscape(fmt.Sprintf("{%s:%s:", m.host, class)) + "*"
	var cursor uint64
	for {
		scan, err := m.client.Do(ctx, m.client.B().Scan().Cursor(cursor).Match(pattern).Count(1000).Build()).AsScanEntry()
		if err != nil {
			return err
		}
		for _, fullKey := range scan.Elements {
			entry, ok, err := m.entry(ctx, class, fullKey)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			if err := fn(entry); err != nil {
				return err
			}
		}
		if cursor = scan.Cursor; cursor == 0 {
			return nil
		}
	}
}

// entry reads one scanned key. ok is false for a key that expired since the
// scan saw it, or one whose class merely starts with the scanned class's name.
func (m *ValkeyCacheManager) entry(ctx context.Context, class, fullKey string) (Entry, bool, error) {
	tag, key, found := strings.Cut(fullKey, "}:")
	if !found {
		return Entry{}, false, nil
	}
	generation, found := strings.CutPrefix(tag, fmt.Sprintf("{%s:%s:", m.host, class))
	if !found || strings.Contains(generation, ":") {
		return Entry{}, false, nil
	}
	replies := m.client.DoMulti(ctx,
		m.client.B().Get().Key(fullKey).Build(),
		m.client.B().Pttl().Key(fullKey).Build())
	value, err := replies[0].ToString()
	if valkey.IsValkeyNil(err) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, err
	}
	pttl, err := replies[1].AsInt64()
	if err != nil {
		return Entry{}, false, err
	}
	entry := Entry{Generation: generation, Key: key, Value: value}
	if pttl > 0 {
		entry.TTL = time.Duration(pttl) * time.Millisecond
	}
	return entry, true, nil
}

// globEscape quotes the characters SCAN's MATCH treats as a pattern.
func globEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\*?[]^`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (m *ValkeyCacheManager) GetCache(class string, opts CacheOptions) Cache {
	m.mu.RLock()
	if cache, ok := m.caches[class]; ok {
		vCache := cache.(*ValkeyCache)
		vCache.mu.Lock()
		if vCache.uncycled != opts.Uncycled {
			vCache.uncycled = opts.Uncycled
			vCache.currentChecksum = generationFor(opts.Uncycled, m.currentChecksum)
			vCache.prefix = m.prefix(class, vCache.currentChecksum)
			vCache.prevPrefix = ""
		}
		if opts.MaxItems != nil {
			vCache.maxItems = *opts.MaxItems
		}
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
	maxItems := 1000
	if opts.MaxItems != nil {
		maxItems = *opts.MaxItems
	}
	cache := &ValkeyCache{
		client:          m.client,
		class:           class,
		currentChecksum: generationFor(opts.Uncycled, m.currentChecksum),
		host:            m.host,
		maxItems:        maxItems,
		uncycled:        opts.Uncycled,
		prefix:          m.prefix(class, generationFor(opts.Uncycled, m.currentChecksum)),
		ttl:             ttl,
	}
	m.caches[class] = cache
	return cache
}
