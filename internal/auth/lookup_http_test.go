package auth

import (
	"strings"
	"testing"

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
