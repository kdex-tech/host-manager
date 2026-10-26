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
	// Update atomically replaces key's entry in the current generation with
	// what fn returns for the entry it holds, and reports whether it wrote.
	// fn returning write=false leaves the entry alone. A concurrent write to
	// key makes fn run again on the new value, so no update is lost; fn must
	// therefore have no side effects.
	Update(ctx context.Context, key string, fn UpdateFunc, opts ...SetOption) (bool, error)
	TTL() time.Duration
	Uncycled() bool
}

// UpdateFunc computes an entry's next value from its current one (found is
// false when there is none). write=false leaves the entry as it is.
type UpdateFunc func(current string, found bool) (next string, write bool)

// initialGeneration is the generation every manager starts at, before the
// host's first Cycle.
const initialGeneration = "0"

// SurvivingGeneration is the one generation of the surviving scope (every
// Uncycled cache). It is fixed, so a replica that first creates the cache
// after a host reconfiguration reads what its peers wrote.
//
// It is initialGeneration because, before it was fixed, an Uncycled cache
// took whatever generation the manager was at when the cache was created:
// "0" for every cache created before the process's first Cycle, which is
// where the auth caches (sessions, codes, registered clients, consent, use
// counters) were found. A cache first created after a Cycle, such as the
// proxy's token cache, starts empty once; every such cache fails closed.
//
// The key shape {host:class:SurvivingGeneration} holds security state (token
// revocations). Changing it strands that state, which un-revokes tokens:
// move the entries with ScanGenerations, never orphan them.
const SurvivingGeneration = initialGeneration

type CacheOptions struct {
	MaxItems *int
	TTL      *time.Duration
	// Uncycled puts the cache in the surviving scope, the one that survives
	// host generations. Anything a request creates and a later request must
	// find again (a revocation, a session, a registered client, a use
	// counter) belongs there. Leaving it false keys the cache on the host's
	// generation, which suits only data that can be rebuilt from the CRs,
	// such as a rendered page: every reconfiguration abandons it.
	//
	// Toward kdex-tech/host-manager#124: a cache will name the scope its
	// generation is keyed on (the whole host, the auth config, ...), and
	// Uncycled is the scope keyed on nothing.
	Uncycled bool
}

// Entry is one cache entry as ScanGenerations reports it.
type Entry struct {
	// Generation is the checksum the entry was written under.
	Generation string
	Key        string
	// TTL is the entry's remaining lifetime; zero when it has none.
	TTL   time.Duration
	Value string
}

type SetOption func(*SetOptions)

type SetOptions struct {
	TTL *time.Duration
}

func applySetOptions(opts []SetOption) SetOptions {
	options := SetOptions{}
	for _, opt := range opts {
		opt(&options)
	}
	return options
}

// generationFor is the generation a cache starts at: the fixed one for the
// surviving scope, the host's current one otherwise.
func generationFor(uncycled bool, current string) string {
	if uncycled {
		return SurvivingGeneration
	}
	return current
}

func WithTTL(ttl time.Duration) SetOption {
	return func(o *SetOptions) {
		o.TTL = &ttl
	}
}

type CacheManager interface {
	// Cycle moves every cycled class to the generation checksum. A class
	// already at checksum is left alone, so its previous generation stays
	// readable. Uncycled classes never move, force or not.
	Cycle(checksum string, force bool) error
	GetCache(class string, opts CacheOptions) Cache
	// ScanGenerations calls fn for every entry this host's class holds under
	// any generation, including generations no Get can reach any more. It is
	// for recovering state a misclassified cache stranded, not for serving.
	// On Valkey it assumes a standalone server: a cluster's SCAN reaches one
	// node.
	ScanGenerations(ctx context.Context, class string, fn func(Entry) error) error
}

func NewCacheManager(addr, host string, ttl *time.Duration) (CacheManager, error) {
	if ttl == nil {
		ttl = new(24 * time.Hour)
	}

	if addr == "" {
		return &InMemoryCacheManager{
			caches:          make(map[string]Cache),
			currentChecksum: initialGeneration,
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
		currentChecksum: initialGeneration,
		host:            host,
		ttl:             *ttl,
	}, nil
}
