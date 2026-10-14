package dcr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
)

// Bounds on one subject's consent record (spec 2026-10-08 §6). Without them an
// authenticated user could grow a single cache value without limit.
const (
	MaxConsentClients   = 64
	MaxConsentRedirects = 4
	MaxConsentScopes    = 32
	MaxConsentScopeLen  = 128

	consentTouchEvery = 24 * time.Hour
	consentTimeout    = 2 * time.Second
)

type consentGrant struct {
	Scopes  []string `json:"s,omitempty"`
	Touched int64    `json:"t"`
}

// consentRecord is ONE subject's consents: client_id -> redirectKey(redirect_uri)
// -> grant.
// One key per subject lets a future "list and revoke your consents" read it
// without a cache scan, which cache.Cache does not offer.
type consentRecord struct {
	Clients map[string]map[string]consentGrant `json:"c"`
}

// ConsentStore remembers which dynamically registered clients a user allowed,
// at which redirect, for which scopes. Uncycled (it must survive a reconcile,
// like the client store, #122), with the client TTL, sliding with use.
//
// Concurrent updates to one subject's record are last-writer-wins. A lost
// Grant only means the user is asked again, so no locking. A Revoke is
// eventually consistent within one cache round trip (cache.Cache has no
// compare-and-set); touch re-loads before saving so it never resurrects it.
type ConsentStore struct {
	cache cache.Cache
	ttl   time.Duration
	now   func() time.Time
}

// NewConsentStore builds the store. maxItems bounds the in-memory backend
// (one item per subject); valkey ignores it. In-memory mode is for dev only.
func NewConsentStore(cm cache.CacheManager, ttl time.Duration, maxItems int) *ConsentStore {
	return NewConsentStoreFromCache(
		cm.GetCache("dcr-consent", cache.CacheOptions{TTL: &ttl, Uncycled: true, MaxItems: &maxItems}), ttl)
}

// NewConsentStoreFromCache builds a ConsentStore over an existing cache.
func NewConsentStoreFromCache(c cache.Cache, ttl time.Duration) *ConsentStore {
	return &ConsentStore{cache: c, ttl: ttl, now: time.Now}
}

func consentKey(subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}

// redirectKey is the fixed-size form a redirect is stored under. Redirects are
// only ever matched exactly, and a registered one may be 2 KB: keyed raw, one
// subject's record could reach half a megabyte, read on every authorize and
// refresh.
func redirectKey(redirectURI string) string {
	sum := sha256.Sum256([]byte(redirectURI))
	return hex.EncodeToString(sum[:])
}

// touchEvery is how stale a grant may get before a read renews the record. The
// read is what keeps a consent in use alive, so it must come well inside the
// TTL; a day caps the writes once the TTL is long.
func (s *ConsentStore) touchEvery() time.Duration {
	if s.ttl <= 0 {
		return consentTouchEvery
	}
	return min(consentTouchEvery, s.ttl/4)
}

func (s *ConsentStore) load(ctx context.Context, subject string) (consentRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, consentTimeout)
	defer cancel()
	rec := consentRecord{Clients: map[string]map[string]consentGrant{}}
	val, ok, _, err := s.cache.Get(ctx, consentKey(subject))
	if err != nil || !ok {
		return rec, err
	}
	if err := json.Unmarshal([]byte(val), &rec); err != nil {
		// An unreadable record is treated as no consent: the user is asked again.
		return consentRecord{Clients: map[string]map[string]consentGrant{}}, nil
	}
	if rec.Clients == nil {
		rec.Clients = map[string]map[string]consentGrant{}
	}
	return rec, nil
}

func (s *ConsentStore) save(ctx context.Context, subject string, rec consentRecord) error {
	ctx, cancel := context.WithTimeout(ctx, consentTimeout)
	defer cancel()
	if len(rec.Clients) == 0 {
		return s.cache.Delete(ctx, consentKey(subject))
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return s.cache.Set(ctx, consentKey(subject), string(b), cache.WithTTL(s.ttl))
}

// Covers reports whether subject allowed clientID at redirectURI for every
// scope in scopes (an empty scopes is covered by any grant for the redirect).
// A stale grant (untouched for a day) is touched, so consent lives as long as
// the client is in use.
func (s *ConsentStore) Covers(ctx context.Context, subject, clientID, redirectURI string, scopes []string) (bool, error) {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return false, err
	}
	g, ok := rec.Clients[clientID][redirectKey(redirectURI)]
	if !ok {
		return false, nil
	}
	for _, sc := range scopes {
		if !slices.Contains(g.Scopes, sc) {
			return false, nil
		}
	}
	s.touchIfStale(ctx, subject, clientID, redirectURI, g)
	return true, nil
}

// HasClient reports whether subject holds consent for clientID at any of
// redirects -- the client's redirects as the current policy allows them, so
// consent given at one the policy has since dropped no longer counts. The
// refresh grant uses it: a session cannot outlive its consent.
func (s *ConsentStore) HasClient(ctx context.Context, subject, clientID string, redirects []string) (bool, error) {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return false, err
	}
	// The most recently touched allowed redirect: if it is fresh, so is the record.
	var newest string
	var grant consentGrant
	found := false
	for _, redirect := range redirects {
		g, ok := rec.Clients[clientID][redirectKey(redirect)]
		if ok && (!found || g.Touched > grant.Touched) {
			newest, grant, found = redirect, g, true
		}
	}
	if found {
		s.touchIfStale(ctx, subject, clientID, newest, grant)
	}
	return found, nil
}

// touchIfStale touches a grant the caller just read, unless that read shows
// it was touched within touchEvery: every covered authorize and every refresh
// reads the record, and only a stale grant should cost the re-load and write.
func (s *ConsentStore) touchIfStale(ctx context.Context, subject, clientID, redirectURI string, read consentGrant) {
	if s.now().Sub(time.Unix(read.Touched, 0)) < s.touchEvery() {
		return
	}
	s.touch(ctx, subject, clientID, redirectURI)
}

// touch re-loads the record right before saving: writing back the caller's
// copy could resurrect a grant revoked since that copy was read.
func (s *ConsentStore) touch(ctx context.Context, subject, clientID, redirectURI string) {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return
	}
	key := redirectKey(redirectURI)
	g, ok := rec.Clients[clientID][key]
	if !ok {
		return
	}
	now := s.now()
	if now.Sub(time.Unix(g.Touched, 0)) < s.touchEvery() {
		return
	}
	g.Touched = now.Unix()
	rec.Clients[clientID][key] = g
	_ = s.save(ctx, subject, rec) // best effort: a failed touch only shortens the consent
}

// Grant records that subject allowed clientID at redirectURI for scopes,
// adding to what was allowed before, within the record's bounds.
func (s *ConsentStore) Grant(ctx context.Context, subject, clientID, redirectURI string, scopes []string) error {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return err
	}
	now := s.now().Unix()
	redirects := rec.Clients[clientID]
	if redirects == nil {
		redirects = map[string]consentGrant{}
	}
	key := redirectKey(redirectURI)
	g := redirects[key]
	merged := slices.Clone(g.Scopes)
	for _, sc := range scopes {
		if len(sc) <= MaxConsentScopeLen && !slices.Contains(merged, sc) {
			merged = append(merged, sc)
		}
	}
	if len(merged) > MaxConsentScopes {
		// Past the cap, keep the most recent MaxConsentScopes of previous + new.
		merged = merged[len(merged)-MaxConsentScopes:]
	}
	slices.Sort(merged)
	redirects[key] = consentGrant{Scopes: merged, Touched: now}
	evictOldest(redirects, MaxConsentRedirects, key, func(g consentGrant) int64 { return g.Touched })
	rec.Clients[clientID] = redirects
	evictOldest(rec.Clients, MaxConsentClients, clientID, func(r map[string]consentGrant) int64 {
		var newest int64
		for _, g := range r {
			newest = max(newest, g.Touched)
		}
		return newest
	})
	return s.save(ctx, subject, rec)
}

// Revoke removes subject's consent for clientID at redirectURI.
func (s *ConsentStore) Revoke(ctx context.Context, subject, clientID, redirectURI string) error {
	rec, err := s.load(ctx, subject)
	if err != nil {
		return err
	}
	delete(rec.Clients[clientID], redirectKey(redirectURI))
	if len(rec.Clients[clientID]) == 0 {
		delete(rec.Clients, clientID)
	}
	return s.save(ctx, subject, rec)
}

// evictOldest drops the least recently touched entries down to limit, never
// the keep entry (just granted; ties on Touched must not evict it).
func evictOldest[V any](m map[string]V, limit int, keep string, touched func(V) int64) {
	for len(m) > limit {
		var oldestKey string
		oldest := int64(1<<63 - 1)
		for k, v := range m {
			if k == keep {
				continue
			}
			if t := touched(v); t < oldest || (t == oldest && k < oldestKey) {
				oldest, oldestKey = t, k
			}
		}
		delete(m, oldestKey)
	}
}
