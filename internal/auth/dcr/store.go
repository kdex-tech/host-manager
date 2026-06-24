package dcr

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/kdex-tech/host-manager/internal/cache"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Client is a dynamically-registered (RFC 7591) OAuth client record.
type Client struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	CreatedAt               int64    `json:"created_at"`
}

type Store struct {
	cache      cache.Cache
	ttl        time.Duration
	maxClients int32
}

func NewStore(cm cache.CacheManager, host string, ttl time.Duration, maxClients int32) *Store {
	// Uncycled: a DCR client registration is session-grade state that
	// refresh tokens are bound to, so it must survive a cache cycle (a
	// routine host config reconcile) the same way refresh-tokens/auth-codes
	// do. Without this, every reconcile rotates the cache prefix and orphans
	// all registered clients, so otherwise-valid refreshes fail with
	// "Invalid client_id". See kdex-tech/host-manager#122.
	return &Store{cache: cm.GetCache("dcr", cache.CacheOptions{TTL: &ttl, Uncycled: true}), ttl: ttl, maxClients: maxClients}
}

func newClientID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "dcr_" + hex.EncodeToString(b), nil
}

func (s *Store) Register(ctx context.Context, c Client) (Client, error) {
	id, err := newClientID()
	if err != nil {
		return Client{}, err
	}
	c.ClientID = id
	if c.TokenEndpointAuthMethod == "" {
		c.TokenEndpointAuthMethod = "none"
	}
	c.CreatedAt = time.Now().Unix()
	blob, err := json.Marshal(c)
	if err != nil {
		return Client{}, err
	}
	if err := s.cache.Set(ctx, id, string(blob), cache.WithTTL(s.ttl)); err != nil {
		return Client{}, err
	}
	return c, nil
}

func (s *Store) Get(ctx context.Context, clientID string) (Client, bool, error) {
	val, found, _, err := s.cache.Get(ctx, clientID)
	if err != nil || !found {
		return Client{}, false, err
	}
	var c Client
	if err := json.Unmarshal([]byte(val), &c); err != nil {
		return Client{}, false, err
	}
	// refresh TTL on use
	if rerr := s.cache.Set(ctx, clientID, val, cache.WithTTL(s.ttl)); rerr != nil {
		logf.FromContext(ctx).Error(rerr, "dcr: TTL refresh failed", "clientID", clientID)
	}
	return c, true, nil
}
