package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	url string
	// resolveURL is the optional password-less subject->claims endpoint used by
	// ResolveClaims (kdex-tech/host-manager#138). Empty when the Secret omits
	// data.resolve-url — the token bridge then simply gets no fresh backend
	// claims (no regression). See resolve-entitlements in user-credential-check.
	resolveURL   string
	sharedSecret []byte
	timeout      time.Duration
	client       *http.Client
}

var _ Lookup = (*httpLookup)(nil)

type credentialCheckRequest struct {
	Subject  string `json:"subject"`
	Password string `json:"password"`
}

type credentialCheckResponse struct {
	OK       bool           `json:"ok"`
	Claims   map[string]any `json:"claims,omitempty"`
	Reason   string         `json:"reason,omitempty"`
	NextStep *string        `json:"next_step,omitempty"`
}

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
		resolveURL:   string(secret.Data["resolve-url"]),
		sharedSecret: sharedSecret,
		timeout:      timeout,
		client:       &http.Client{Timeout: timeout},
	}, nil
}

type resolveClaimsResponse struct {
	Claims map[string]any `json:"claims,omitempty"`
}

// ResolveClaims performs a password-less, subject-only lookup of the subject's
// backend claims (e.g. vs_entitlements) against resolveURL, signed with the same
// HMAC contract as FindInternal. Returns (nil, nil) when resolveURL is not
// configured, so a host without the endpoint wired simply gets no fresh backend
// claims. See kdex-tech/host-manager#138.
func (hl *httpLookup) ResolveClaims(subject string) (jwt.MapClaims, error) {
	if hl.resolveURL == "" || subject == "" {
		return nil, nil
	}

	body, err := json.Marshal(struct {
		Subject string `json:"subject"`
	}{Subject: subject})
	if err != nil {
		return nil, fmt.Errorf("httpLookup: marshal resolve request: %w", err)
	}

	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sig := computeSignature(hl.sharedSecret, ts, body)

	ctx, cancel := context.WithTimeout(context.Background(), hl.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hl.resolveURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("httpLookup: build resolve request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-K-CNAS-Lookup-Timestamp", ts)
	req.Header.Set("X-K-CNAS-Lookup-Signature", sig)

	resp, err := hl.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpLookup: resolve request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpLookup: resolve returned status %d", resp.StatusCode)
	}

	var parsed resolveClaimsResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("httpLookup: decode resolve response: %w", err)
	}
	if len(parsed.Claims) == 0 {
		return nil, nil
	}
	return jwt.MapClaims(parsed.Claims), nil
}

func (hl *httpLookup) Type() string {
	return HTTP
}

func (hl *httpLookup) FindInternal(subject string, password string) (bool, jwt.MapClaims, error) {
	body, err := json.Marshal(credentialCheckRequest{Subject: subject, Password: password})
	if err != nil {
		return false, nil, fmt.Errorf("httpLookup: marshal request: %w", err)
	}

	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	sig := computeSignature(hl.sharedSecret, ts, body)

	ctx, cancel := context.WithTimeout(context.Background(), hl.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hl.url, bytes.NewReader(body))
	if err != nil {
		return false, nil, fmt.Errorf("httpLookup: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-K-CNAS-Lookup-Timestamp", ts)
	req.Header.Set("X-K-CNAS-Lookup-Signature", sig)

	resp, err := hl.client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("httpLookup: request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("httpLookup: server returned status %d", resp.StatusCode)
	}

	var parsed credentialCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return false, nil, fmt.Errorf("httpLookup: decode response: %w", err)
	}

	if !parsed.OK {
		reason := parsed.Reason
		if reason == "" {
			reason = "invalid_credentials"
		}
		return false, nil, fmt.Errorf("httpLookup: credential check failed: %s", reason)
	}

	claims := jwt.MapClaims(parsed.Claims)
	if claims == nil {
		claims = jwt.MapClaims{}
	}
	if parsed.NextStep != nil && *parsed.NextStep != "" {
		claims["next_step"] = *parsed.NextStep
	}
	return true, claims, nil
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
