package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
)

const (
	// clientRegistryClass is the surviving (Uncycled) cache class holding every
	// client id this host has ever had configured, so a client removed from
	// config is still recognised as a client. See kdex-tech/host-manager#255.
	clientRegistryClass = "client-registry"
	clientRegistryKey   = "ids"
)

// loadClientRegistry records the ids of configured in the client registry and
// returns every id the registry holds: the configured ones plus every one a
// previous configuration (or a peer replica) recorded.
//
// The merge is one atomic Update of a sorted JSON array, so concurrent builds
// lose nothing, and only grows: an id is never removed, because the point is
// that credentials issued to a removed client must not later classify as a
// User. dcr_ ids are not recorded; NamesClient matches them by prefix. A nil
// cm returns just the configured ids.
func loadClientRegistry(
	ctx context.Context,
	cm cache.CacheManager,
	configured map[string]AuthClient,
) (map[string]struct{}, error) {
	ids := make([]string, 0, len(configured))
	for id := range configured {
		if id != "" && !strings.HasPrefix(id, dcr.ClientIDPrefix) {
			ids = append(ids, id)
		}
	}
	if cm == nil {
		return toSet(ids), nil
	}

	store := cm.GetCache(clientRegistryClass, cache.CacheOptions{MaxItems: new(0), Uncycled: true})
	// fnErr is the closure's failure. An unreadable stored value must fail the
	// build, never be replaced by a partial registry: that would forget the
	// removed clients it held and fail open.
	var fnErr error
	if _, err := store.Update(ctx, clientRegistryKey, func(current string, found bool) (string, bool) {
		fnErr = nil
		var have []string
		if found {
			if err := json.Unmarshal([]byte(current), &have); err != nil {
				fnErr = fmt.Errorf("decode stored ids: %w", err)
				return "", false
			}
		}
		merged := toSet(have)
		grew := !found
		for _, id := range ids {
			if _, ok := merged[id]; !ok {
				merged[id] = struct{}{}
				grew = true
			}
		}
		if !grew {
			return "", false
		}
		out := make([]string, 0, len(merged))
		for id := range merged {
			out = append(out, id)
		}
		slices.Sort(out)
		b, err := json.Marshal(out)
		if err != nil {
			fnErr = fmt.Errorf("encode ids: %w", err)
			return "", false
		}
		return string(b), true
		// No expiry: a nil TTL means the manager default (24h), after which
		// the registry would vanish and rebuild from current config only.
	}, cache.WithoutExpiry()); err != nil {
		return nil, fmt.Errorf("client registry: update: %w", err)
	}
	if fnErr != nil {
		return nil, fmt.Errorf("client registry: %w", fnErr)
	}

	value, found, _, err := store.Get(ctx, clientRegistryKey)
	if err != nil {
		return nil, fmt.Errorf("client registry: read: %w", err)
	}
	registry := toSet(ids)
	if found {
		var stored []string
		if err := json.Unmarshal([]byte(value), &stored); err != nil {
			return nil, fmt.Errorf("client registry: decode: %w", err)
		}
		for _, id := range stored {
			registry[id] = struct{}{}
		}
	}
	return registry, nil
}

func toSet(ids []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}
