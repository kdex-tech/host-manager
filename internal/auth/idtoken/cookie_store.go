package idtoken

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	kdexhttp "github.com/kdex-tech/host-manager/internal/http"
)

type CookieIDTokenStore struct {
	BlockKey string
	TTL      time.Duration
}

var _ IDTokenStore = (*CookieIDTokenStore)(nil)

func (c *CookieIDTokenStore) Set(w http.ResponseWriter, r *http.Request, rawIDToken string) error {
	options := &http.Cookie{
		Path:     "/",
		HttpOnly: true,
		Secure:   kdexhttp.IsSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(c.TTL.Seconds()),
	}

	return c.encryptAndSplit(w, r, hintName, rawIDToken, options)
}

func (c *CookieIDTokenStore) Get(r *http.Request) (string, error) {
	return c.getAndDecryptToken(r, hintName)
}

func NewCookieIDTokenStore(blockKey string, ttl time.Duration) IDTokenStore {
	return &CookieIDTokenStore{
		BlockKey: blockKey,
		TTL:      ttl,
	}
}

func (c *CookieIDTokenStore) encryptAndSplit(w http.ResponseWriter, r *http.Request, name string, token string, options *http.Cookie) error {
	// 1. Encrypt the whole string first
	block, err := aes.NewCipher([]byte(c.BlockKey))
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Ciphertext contains Nonce + Encrypted Data + Tag
	ciphertext := gcm.Seal(nonce, nonce, []byte(token), nil)

	// 2. Encode to Base64 (cookies must be ASCII)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	// 3. Use your splitter logic on the 'encoded' string
	c.setSplitCookies(w, r, name, encoded, options)
	return nil
}

func (c *CookieIDTokenStore) getAndDecryptToken(r *http.Request, name string) (string, error) {
	// 1. Reassemble Base64 string from chunks
	encoded := c.getIDTokenFromSplitCookies(r, name)
	if encoded == "" {
		return "", errors.New("no token found")
	}

	// 2. Decode Base64
	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// 3. Decrypt
	block, err := aes.NewCipher([]byte(c.BlockKey))
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create gcm: %w", err)
	}
	nonceSize := gcm.NonceSize()

	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return "", err // Message tampered with or wrong key
	}

	return string(plaintext), nil
}

func (c *CookieIDTokenStore) getIDTokenFromSplitCookies(r *http.Request, name string) string {
	var fullToken strings.Builder

	// Start from index 0 and keep looking for the next numbered chunk
	for i := 0; ; i++ {
		chunkName := fmt.Sprintf("%s_%d", name, i)
		cookie, err := r.Cookie(chunkName)

		// As soon as a chunk is missing (e.g., oidc_hint_3), we assume
		// we have reached the end of the stored data.
		if err != nil {
			break
		}

		fullToken.WriteString(cookie.Value)
	}

	return fullToken.String()
}

func (c *CookieIDTokenStore) setSplitCookies(w http.ResponseWriter, r *http.Request, name string, value string, options *http.Cookie) {
	// 1. Define the safe chunk size.
	// We use 3000 to leave plenty of room for the cookie name, metadata,
	// and overhead in the HTTP header limit.
	const chunkSize = 3000

	// 2. CLEANUP: Delete any existing chunks.
	// If a user previously had 5 chunks but now only has 2, the browser
	// would keep chunks 3 and 4, which would corrupt the next reassembly.
	for i := 0; ; i++ {
		chunkName := fmt.Sprintf("%s_%d", name, i)
		_, err := r.Cookie(chunkName)
		if err != nil {
			// No more existing chunks found in the request
			break
		}

		// Delete the cookie
		cleanup := *options
		cleanup.Name = chunkName
		cleanup.Value = ""
		cleanup.MaxAge = -1
		http.SetCookie(w, &cleanup)
	}

	// 3. CHUNKING: Split the value and set new cookies.
	// We treat the value as a slice of bytes to ensure we don't
	// break multi-byte characters (though Base64 is safe).
	data := []byte(value)
	totalLen := len(data)

	for i := 0; i*chunkSize < totalLen; i++ {
		start := i * chunkSize
		end := min(start+chunkSize, totalLen)

		chunk := *options
		chunk.Name = fmt.Sprintf("%s_%d", name, i)
		chunk.Value = string(data[start:end])

		http.SetCookie(w, &chunk)
	}
}
