package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/kdex-tech/host-manager/internal/auth/dcr"
	"github.com/kdex-tech/host-manager/internal/cache"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// clientRegistryClass is the surviving (Uncycled) cache class holding a
	// record of every client id this host has ever had configured, so a
	// client removed from config is still recognised as a client, and a
	// client added back does not revive what it held before its removal.
	// See kdex-tech/host-manager#255.
	clientRegistryClass = "client-registry"
	clientRegistryKey   = "ids"
)

// clientRegistryTimeout bounds the registry's cache I/O in NewExchanger: one
// Get, and on a change one Update, which against Valkey is up to 16
// WATCH/GET/MULTI rounds under contention. It runs once per Exchanger build
// on the reconcile path, never per request, so it can afford far more than
// the session-grant refresh's 50ms. What it must not do is wait forever:
// without a deadline a hung Valkey wedges the reconcile worker. At the
// deadline the build fails, the previous Exchanger keeps serving and the
// reconcile retries with backoff. A var so a test can shorten it.
var clientRegistryTimeout = 5 * time.Second

// clientRegistryNow is the registry's clock, read once per merge: the time a
// removal is recorded at. A var so a test can place removals in time.
var clientRegistryNow = time.Now

// clientRecord is what the registry remembers of one client id.
//
// The stored value of the registry key is a JSON object from client id to
// record, written with its keys sorted:
//
//	{"<id>": {"present": true|false, "removedAt": <unix seconds>}, ...}
//
// Its fields:
//   - present: the id is in the configuration of the latest Exchanger build
//     that merged it.
//   - removedAt: the cutoff, in unix seconds; 0 means the id has never been
//     removed. It is stamped when a build first sees the id leave the
//     configuration, and stamped again when a build sees it come back, so
//     every credential issued at or before the re-add stays refused (the
//     veto), whichever Exchanger minted it.
//
// The registry has never shipped in another shape, so there is no
// migration: a value in any other shape (an array, an unknown field, a null
// record, a negative removedAt) is corrupt and fails the build closed.
type clientRecord struct {
	Present   bool  `json:"present"`
	RemovedAt int64 `json:"removedAt"`
}

// clientRegistryLocation names the registry's full key, the shape an
// operator searches Valkey for (the surviving scope is
// {<host>:<class>:<generation>}:<key>), so a registry error can be acted on.
var clientRegistryLocation = fmt.Sprintf("client registry (Valkey key {<host>:%s:%s}:%s)",
	clientRegistryClass, cache.SurvivingGeneration, clientRegistryKey)

// loadClientRegistry merges the ids of configured into the client registry
// and returns every record the registry holds after the merge: the
// configured ids, present, and every id a previous configuration (or a peer
// replica) recorded. It is called at the very end of NewExchanger, so a
// configuration whose Exchanger never builds reserves nothing.
//
// The merge (mergeClientRegistry) only ever adds records or marks them
// removed, never deletes one: credentials issued to a removed client must
// not later classify as a User. dcr_ ids are never recorded; NamesClient
// matches them by prefix. A nil cm returns just the configured ids.
//
// The common case, a build whose configuration the registry already
// reflects, costs one Get and writes nothing. Otherwise the merge runs as
// one atomic Update, so concurrent builds lose nothing, and its result is
// the one the last attempt computed: there is no second read, which an
// eviction between the two could have answered with a partial registry.
//
// Every id newly recorded, re-added or newly marked removed is logged at
// V(0). Client ids are operator configuration, not a user's identity.
func loadClientRegistry(
	ctx context.Context,
	cm cache.CacheManager,
	configured map[string]AuthClient,
) (map[string]clientRecord, error) {
	ids := make([]string, 0, len(configured))
	for id := range configured {
		if id != "" && !strings.HasPrefix(id, dcr.ClientIDPrefix) {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)
	if cm == nil {
		registry := make(map[string]clientRecord, len(ids))
		for _, id := range ids {
			registry[id] = clientRecord{Present: true}
		}
		return registry, nil
	}

	ctx, cancel := context.WithTimeout(ctx, clientRegistryTimeout)
	defer cancel()
	now := clientRegistryNow().Unix()
	store := cm.GetCache(clientRegistryClass, cache.CacheOptions{MaxItems: new(0), Uncycled: true})

	// The fast path: a stored registry that already reflects this
	// configuration is used as it is. An unreadable one fails here, exactly
	// as the Update below would.
	value, found, _, err := store.Get(ctx, clientRegistryKey)
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", clientRegistryLocation, err)
	}
	if found {
		have, err := decodeClientRegistry(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", clientRegistryLocation, err)
		}
		if m := mergeClientRegistry(have, ids, now); !m.changed {
			return m.registry, nil
		}
	}

	// fnErr is the closure's failure, and merged its result, both from the
	// last attempt. An unreadable stored value must fail the build, never be
	// replaced by a partial registry: that would forget the removed clients
	// it held and fail open.
	var (
		fnErr  error
		merged registryMerge
	)
	if _, err := store.Update(ctx, clientRegistryKey, func(current string, found bool) (string, bool) {
		fnErr = nil
		have := map[string]clientRecord{}
		if found {
			if have, fnErr = decodeClientRegistry(current); fnErr != nil {
				return "", false
			}
		}
		merged = mergeClientRegistry(have, ids, now)
		if found && !merged.changed {
			return "", false
		}
		// json.Marshal writes a map's keys sorted.
		b, err := json.Marshal(merged.registry)
		if err != nil {
			fnErr = fmt.Errorf("encode: %w", err)
			return "", false
		}
		return string(b), true
		// No expiry: a nil TTL means the manager default (24h), after which
		// the registry would vanish and rebuild from current config only.
	}, cache.WithoutExpiry()); err != nil {
		return nil, fmt.Errorf("%s: update: %w", clientRegistryLocation, err)
	}
	if fnErr != nil {
		return nil, fmt.Errorf("%s: %w", clientRegistryLocation, fnErr)
	}

	log := logf.FromContext(ctx)
	for _, id := range merged.recorded {
		log.Info("client registry: recorded a configured client id; it stays reserved as a client's name",
			"client_id", id)
	}
	for _, id := range merged.readded {
		log.Info("client registry: client re-added; credentials issued before now are refused",
			"client_id", id, "removed_at", merged.registry[id].RemovedAt)
	}
	for _, id := range merged.removed {
		log.Info("client registry: marked a client id removed; credentials it was issued until now stay refused, even if it is added back",
			"client_id", id, "removed_at", merged.registry[id].RemovedAt)
	}
	return merged.registry, nil
}

// registryMerge is the outcome of one merge.
type registryMerge struct {
	registry map[string]clientRecord
	// recorded are the configured ids the registry had no record of,
	// readded the configured ids it had recorded removed, and removed the
	// ids newly marked removed. All sorted.
	recorded, readded, removed []string
	changed                    bool
}

// mergeClientRegistry merges the configured ids (sorted) into have, at now
// (unix seconds), without modifying have:
//
//   - a new configured id is present, never removed (removedAt 0);
//   - a configured id recorded removed is re-added: present, with removedAt
//     moved to now (Ruling Q3, quad 2026-10-28);
//   - a configured id already present keeps its removedAt;
//   - an id that was present but is no longer configured is marked removed
//     at now;
//   - an id already absent stays as it is.
//
// removedAt only ever moves forward (max, against a peer whose clock runs
// ahead), and no record is ever dropped.
//
// Why the re-add stamps the cutoff again: the removal is recorded by the
// first build that sees the id gone, but an Exchanger still configuring it
// keeps minting for a while (the old one a reconcile keeps serving until the
// new one is set, a peer replica still on the old config). Everything those
// mint is issued before the re-add, so the re-add's cutoff refuses it all.
// The cost: a credential issued in the very second of the re-add is refused
// once.
func mergeClientRegistry(have map[string]clientRecord, configured []string, now int64) registryMerge {
	m := registryMerge{registry: make(map[string]clientRecord, len(have)+len(configured))}
	for id, rec := range have {
		m.registry[id] = rec
	}
	isConfigured := make(map[string]struct{}, len(configured))
	for _, id := range configured {
		isConfigured[id] = struct{}{}
		rec, known := m.registry[id]
		switch {
		case !known:
			m.registry[id] = clientRecord{Present: true}
			m.recorded = append(m.recorded, id)
		case !rec.Present:
			rec.Present = true
			rec.RemovedAt = max(rec.RemovedAt, now)
			m.registry[id] = rec
			m.readded = append(m.readded, id)
		}
	}
	for id, rec := range m.registry {
		if _, ok := isConfigured[id]; rec.Present && !ok {
			rec.Present = false
			rec.RemovedAt = max(rec.RemovedAt, now)
			m.registry[id] = rec
			m.removed = append(m.removed, id)
		}
	}
	slices.Sort(m.removed)
	m.changed = len(m.recorded) > 0 || len(m.readded) > 0 || len(m.removed) > 0
	return m
}

// decodeClientRegistry decodes a stored registry, refusing every value that
// is not exactly the clientRecord format.
func decodeClientRegistry(value string) (map[string]clientRecord, error) {
	dec := json.NewDecoder(strings.NewReader(value))
	dec.DisallowUnknownFields()
	var stored map[string]*clientRecord
	if err := dec.Decode(&stored); err != nil {
		return nil, fmt.Errorf("decode stored records: %w", err)
	}
	// Nothing may follow the object, not even a stray `}` or `]`, which
	// dec.More() does not report.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode stored records: trailing data")
	}
	if stored == nil {
		return nil, errors.New("decode stored records: not an object")
	}
	registry := make(map[string]clientRecord, len(stored))
	for id, rec := range stored {
		if rec == nil || rec.RemovedAt < 0 {
			return nil, fmt.Errorf("decode stored records: client id %q has an invalid record", id)
		}
		registry[id] = *rec
	}
	return registry, nil
}
