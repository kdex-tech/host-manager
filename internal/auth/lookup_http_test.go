package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeHTTPLookupSecret(t *testing.T, url, timeout string, sharedSecret []byte) corev1.Secret {
	t.Helper()
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rsi-dev-http-lookup-auth",
			Namespace: "rsi-dev",
			Annotations: map[string]string{
				"kdex.dev/secret-type": "http-lookup-auth",
				"kdex.dev/active-key":  "true",
			},
		},
		Data: map[string][]byte{
			"shared-secret": sharedSecret,
			"url":           []byte(url),
			"timeout-ms":    []byte(timeout),
		},
	}
}

func TestNewHTTPLookup_ValidSecret(t *testing.T) {
	sec := makeHTTPLookupSecret(t,
		"http://user-credential-check.rsi-dev.svc.cluster.local/v1/credential-check",
		"2000",
		make([]byte, 32),
	)
	lookup, err := NewHTTPLookup(sec)
	if err != nil {
		t.Fatalf("NewHTTPLookup returned error: %v", err)
	}
	if lookup == nil {
		t.Fatal("NewHTTPLookup returned nil")
	}
	if lookup.Type() != "http" {
		t.Errorf("Type() = %q; want %q", lookup.Type(), "http")
	}
}

func TestNewHTTPLookup_MissingURL(t *testing.T) {
	sec := makeHTTPLookupSecret(t, "", "2000", make([]byte, 32))
	_, err := NewHTTPLookup(sec)
	if err == nil {
		t.Fatal("expected error for missing url, got nil")
	}
	if !strings.Contains(err.Error(), "url") {
		t.Errorf("error %q should mention 'url'", err.Error())
	}
}

func TestNewHTTPLookup_SharedSecretTooShort(t *testing.T) {
	sec := makeHTTPLookupSecret(t,
		"http://example/",
		"2000",
		make([]byte, 16),
	)
	_, err := NewHTTPLookup(sec)
	if err == nil {
		t.Fatal("expected error for short shared-secret, got nil")
	}
}

func TestNewHTTPLookup_DefaultTimeout(t *testing.T) {
	sec := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "y"},
		Data: map[string][]byte{
			"shared-secret": make([]byte, 32),
			"url":           []byte("http://example/"),
		},
	}
	lookup, err := NewHTTPLookup(sec)
	if err != nil {
		t.Fatalf("NewHTTPLookup error: %v", err)
	}
	if lookup.timeout.Milliseconds() != 2000 {
		t.Errorf("default timeout = %v ms; want 2000", lookup.timeout.Milliseconds())
	}
}

func TestNewHTTPLookup_InvalidTimeoutMS(t *testing.T) {
	sec := makeHTTPLookupSecret(t, "http://example/", "not-a-number", make([]byte, 32))
	_, err := NewHTTPLookup(sec)
	if err == nil {
		t.Fatal("expected error for non-integer timeout-ms, got nil")
	}
	if !strings.Contains(err.Error(), "timeout-ms") {
		t.Errorf("error %q should mention 'timeout-ms'", err.Error())
	}
}

func TestComputeSignature_Deterministic(t *testing.T) {
	secret := []byte("12345678901234567890123456789012") // 32 bytes
	body := []byte(`{"subject":"alice","password":"hunter2"}`)
	timestamp := "1715000000000"

	sig := computeSignature(secret, timestamp, body)

	// Recompute independently to verify the format
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if sig != want {
		t.Errorf("computeSignature = %q; want %q", sig, want)
	}
}

func TestComputeSignature_DifferentSecretsDiffer(t *testing.T) {
	body := []byte(`x`)
	ts := "1"
	a := computeSignature([]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ts, body)
	b := computeSignature([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), ts, body)
	if a == b {
		t.Error("signatures should differ for different secrets")
	}
}

func TestHTTPLookup_FindInternal_Success(t *testing.T) {
	secret := []byte("12345678901234567890123456789012")
	var receivedBody []byte
	var receivedSig, receivedTS string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		receivedSig = r.Header.Get("X-K-CNAS-Lookup-Signature")
		receivedTS = r.Header.Get("X-K-CNAS-Lookup-Timestamp")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"ok": true,
			"claims": {
				"sub": "01950ea5-7c41-7a16-9c7c-c8e1e0d8f8a3",
				"email": "alice@example.com",
				"email_verified": true,
				"given_name": "Alice",
				"amr": ["pwd"],
				"acr": "1"
			},
			"next_step": null
		}`))
	}))
	defer srv.Close()

	lookup, err := NewHTTPLookup(makeHTTPLookupSecret(t, srv.URL, "2000", secret))
	if err != nil {
		t.Fatalf("NewHTTPLookup: %v", err)
	}

	ok, claims, err := lookup.FindInternal("alice@example.com", "hunter2")
	if err != nil {
		t.Fatalf("FindInternal: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if claims["sub"] != "01950ea5-7c41-7a16-9c7c-c8e1e0d8f8a3" {
		t.Errorf("claims[sub] = %v; want UUID", claims["sub"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("claims[email] = %v", claims["email"])
	}

	// Verify the server actually received what we promised
	var sent struct {
		Subject  string `json:"subject"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(receivedBody, &sent); err != nil {
		t.Fatalf("could not parse received body: %v", err)
	}
	if sent.Subject != "alice@example.com" || sent.Password != "hunter2" {
		t.Errorf("received body unexpected: %s", receivedBody)
	}

	// Verify signature matches
	want := computeSignature(secret, receivedTS, receivedBody)
	if receivedSig != want {
		t.Errorf("server-received signature %q does not match HMAC over body+ts (%q)", receivedSig, want)
	}

	// Verify timestamp is recent
	ts, _ := strconv.ParseInt(receivedTS, 10, 64)
	age := time.Since(time.UnixMilli(ts))
	if age < 0 || age > 5*time.Second {
		t.Errorf("timestamp %d is %v old; expected fresh", ts, age)
	}
}
