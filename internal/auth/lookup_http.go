package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	corev1 "k8s.io/api/core/v1"
)

const (
	HTTPLookupSecretType = "http-lookup-auth"

	defaultHTTPLookupTimeout = 2 * time.Second
	minSharedSecretBytes     = 32
)

type httpLookup struct {
	url          string
	sharedSecret []byte
	timeout      time.Duration
	client       *http.Client
}

var _ Lookup = (*httpLookup)(nil)

// NewHTTPLookup constructs a Lookup that POSTs credentials to an external HTTP
// endpoint identified by the Secret's data.url field, signing requests with
// HMAC-SHA256 using data.shared-secret as the key.
func NewHTTPLookup(secret corev1.Secret) (*httpLookup, error) {
	url := string(secret.Data["url"])
	if url == "" {
		return nil, errors.New("http-lookup-auth Secret missing required 'url' data field")
	}

	sharedSecret := secret.Data["shared-secret"]
	if len(sharedSecret) < minSharedSecretBytes {
		return nil, fmt.Errorf("http-lookup-auth Secret 'shared-secret' must be at least %d bytes (got %d)",
			minSharedSecretBytes, len(sharedSecret))
	}

	timeout := defaultHTTPLookupTimeout
	if raw := string(secret.Data["timeout-ms"]); raw != "" {
		ms, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("http-lookup-auth Secret 'timeout-ms' is not a valid integer: %w", err)
		}
		timeout = time.Duration(ms) * time.Millisecond
	}

	return &httpLookup{
		url:          url,
		sharedSecret: sharedSecret,
		timeout:      timeout,
		client:       &http.Client{Timeout: timeout},
	}, nil
}

func (hl *httpLookup) Type() string {
	return "http"
}

// FindInternal is implemented in a subsequent task. Stub for now.
func (hl *httpLookup) FindInternal(subject string, password string) (bool, jwt.MapClaims, error) {
	return false, nil, errors.New("not implemented")
}

// computeSignature returns hex(hmac-sha256(secret, timestamp + "." + body)).
// The format is mirrored by the credential-check function for verification.
func computeSignature(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}
