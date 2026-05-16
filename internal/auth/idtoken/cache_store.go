package idtoken

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/kdex-tech/host-manager/internal/cache"
	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
)

type CacheIDTokenStore struct {
	cache cache.Cache
}

var _ IDTokenStore = (*CacheIDTokenStore)(nil)

func (c *CacheIDTokenStore) Set(w http.ResponseWriter, r *http.Request, rawIDToken string) error {
	oidcSessionId := uuid.New().String()

	// set the cookie
	cookie := &http.Cookie{
		Name:     hintName,
		Value:    oidcSessionId,
		Path:     "/",
		HttpOnly: true,
		Secure:   kdexhttp.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(c.cache.TTL().Seconds()),
	}
	http.SetCookie(w, cookie)

	return c.cache.Set(r.Context(), oidcSessionId, rawIDToken)
}

func (c *CacheIDTokenStore) Get(r *http.Request) (string, error) {
	cookie, err := r.Cookie(hintName)
	if err != nil {
		return "", err
	}
	idToken, ok, _, err := c.cache.Get(r.Context(), cookie.Value)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("no token found")
	}
	return idToken, nil
}

func NewCacheIDTokenStore(cacheManager cache.CacheManager, ttl time.Duration) IDTokenStore {
	return &CacheIDTokenStore{
		cache: cacheManager.GetCache(hintName, cache.CacheOptions{
			Uncycled: true,
			TTL:      &ttl,
		}),
	}
}
