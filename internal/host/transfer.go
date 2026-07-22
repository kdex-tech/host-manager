package host

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
)

// transferKeyPrefix namespaces URL-delivery records in the shared "cap" cache
// class (the same class holding the "uses:<jti>" budget counters).
const transferKeyPrefix = "transfer:"

// transferRecord is the server-side capability a /-/transfer/<handle> URL maps
// back to. Claims-only: the signed JWT is never stored or embedded in the URL —
// the unguessable handle plus this record IS the credential, and downstream
// enforcement re-checks the entitlements.
type transferRecord struct {
	JTI          string         `json:"jti"`
	Sub          string         `json:"sub"`
	Entitlements []string       `json:"entitlements"`
	Target       TransferTarget `json:"target"`
}

// newTransferHandle returns a 256-bit unguessable, URL-safe handle.
func newTransferHandle() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// capCache returns the host's bounded-capability cache (nil when no cache
// manager is configured — envtest/dev without Valkey).
func (hh *HostHandler) capCache() cache.Cache {
	if hh.cacheManager == nil {
		return nil
	}
	return hh.cacheManager.GetCache("cap", cache.CacheOptions{Uncycled: true})
}

// storeTransferRecord persists rec under transfer:<handle> with the given TTL.
func (hh *HostHandler) storeTransferRecord(ctx context.Context, handle string, rec transferRecord, ttl time.Duration) error {
	c := hh.capCache()
	if c == nil {
		return errNoCache
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return c.Set(ctx, transferKeyPrefix+handle, string(b), cache.WithTTL(ttl))
}

// loadTransferRecord reads and decodes the record for handle. ok=false on a
// missing/expired key, a read error, or a decode error (all fail-closed).
func (hh *HostHandler) loadTransferRecord(ctx context.Context, handle string) (transferRecord, bool) {
	c := hh.capCache()
	if c == nil {
		return transferRecord{}, false
	}
	val, exists, _, err := c.Get(ctx, transferKeyPrefix+handle)
	if err != nil || !exists {
		return transferRecord{}, false
	}
	var rec transferRecord
	if json.Unmarshal([]byte(val), &rec) != nil {
		return transferRecord{}, false
	}
	return rec, true
}

// transferBaseURL is the caller-facing scheme://host prefix for a redemption
// URL, derived from the forwarded request address; "" when unknown.
func transferBaseURL(r *http.Request) string {
	host := fwdHost(r)
	if host == "" {
		return ""
	}
	return fwdScheme(r) + "://" + host
}

// errNoCache is returned when URL delivery is requested but no cache manager is
// available to hold the handle record / budget counter.
var errNoCache = fmt.Errorf("mint_token url delivery requires a configured cache")
