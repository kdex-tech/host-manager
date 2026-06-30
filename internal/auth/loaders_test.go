package auth

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

// authClientSecret builds an auth-client Secret from string key/value data.
func authClientSecret(data map[string]string) corev1.Secret {
	d := map[string][]byte{}
	for k, v := range data {
		d[k] = []byte(v)
	}
	return corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "auth-client",
			Annotations: map[string]string{"kdex.dev/secret-type": "auth-client"},
		},
		Data: d,
	}
}

// TestAuthClientLoaderRejectsPublicCustomSchemeWithoutPKCE pins the footgun
// guard: a statically-configured public client whose redirect uses an RFC 8252
// private-use (custom) URI scheme is open to authorization-code interception
// unless PKCE is required. The loader must fail closed (and surface a clear,
// actionable error) rather than silently load an insecure client.
func TestAuthClientLoaderRejectsPublicCustomSchemeWithoutPKCE(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id":     "interviewer",
		"public":        "true",
		"redirect_uris": "ai.knowdrive.interviewer://oauth",
	})}
	if _, err := AuthClientLoader(secrets); err == nil {
		t.Fatal("expected error for public custom-scheme client without require_pkce")
	} else if !strings.Contains(err.Error(), "require_pkce") {
		t.Fatalf("error should mention require_pkce, got: %v", err)
	}
}

// TestAuthClientLoaderAllowsPublicCustomSchemeWithPKCE proves the guard is
// satisfied when the operator opts into PKCE.
func TestAuthClientLoaderAllowsPublicCustomSchemeWithPKCE(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id":     "interviewer",
		"public":        "true",
		"require_pkce":  "true",
		"redirect_uris": "ai.knowdrive.interviewer://oauth",
	})}
	clients, err := AuthClientLoader(secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := clients["interviewer"]; !ok {
		t.Fatal("client should be loaded")
	}
}

// TestAuthClientLoaderAllowsPublicHTTPSWithoutPKCE ensures the guard targets
// only custom-scheme redirects: a public https client without PKCE is a normal,
// allowed configuration and must not be rejected.
func TestAuthClientLoaderAllowsPublicHTTPSWithoutPKCE(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id":     "web",
		"public":        "true",
		"redirect_uris": "https://app.knowdrive.ai/cb",
	})}
	if _, err := AuthClientLoader(secrets); err != nil {
		t.Fatalf("https public client without PKCE must load: %v", err)
	}
}
