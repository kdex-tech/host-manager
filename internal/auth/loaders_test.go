package auth

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// authClientSecretNamed is authClientSecret with an explicit namespace/name, so
// a test can prove an error names BOTH objects that collide. A duplicate client
// id is only actionable when the message says which two Secrets to look at.
func authClientSecretNamed(namespace, name string, data map[string]string) corev1.Secret {
	s := authClientSecret(data)
	s.Namespace = namespace
	s.Name = name
	return s
}

// TestAuthClientLoaderRejectsDuplicateClientID pins kdex-tech/host-manager#297.
//
// The loader builds map[clientID]client with no duplicate detection, so two
// Secrets declaring one client id resolve last-one-wins. The loser is inert: an
// operator rotating its client-secret changes nothing, the token endpoint keeps
// comparing against the winner's value and answers invalid_client /
// "client authentication failed", and the host log says only
// "invalid client_secret" — which reads as "rotated but stale" and is really
// "you edited a shadow". Which Secret wins depends on list order, so the
// effective credential can also flap between reconciles.
//
// Fail closed at load time, naming both objects, rather than serve a credential
// nothing in the system reports.
func TestAuthClientLoaderRejectsDuplicateClientID(t *testing.T) {
	first := authClientSecretNamed("spike2", "troubleshooting-spike2", map[string]string{
		"client-id":     "troubleshooting-spike2",
		"client-secret": "first",
		"redirect-uris": "https://example.test/callback",
	})
	second := authClientSecretNamed("spike2", "troubleshooting-spike2-client", map[string]string{
		"client-id":     "troubleshooting-spike2",
		"client-secret": "second",
		"redirect-uris": "https://example.test/callback",
	})

	// Both orders: the pairing is what is wrong, not which object came first.
	for name, secrets := range map[string]kdexv1alpha1.Secrets{
		"registered first": {first, second},
		"client first":     {second, first},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := AuthClientLoader(secrets)
			require.Error(t, err, "a client id declared by two Secrets must not load")
			for _, want := range []string{
				"spike2/troubleshooting-spike2",
				"spike2/troubleshooting-spike2-client",
				"troubleshooting-spike2",
			} {
				assert.Contains(t, err.Error(), want,
					"the error must name both Secrets and the id so an operator can find them")
			}
		})
	}
}

// TestAuthClientLoaderAcceptsDistinctClientIDs proves the duplicate guard is
// specific to a collision and does not reject a host with many clients — the
// ordinary case, including two Secrets that share a description or grants.
func TestAuthClientLoaderAcceptsDistinctClientIDs(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{
		authClientSecretNamed("ns", "one", map[string]string{
			"client-id": "one", "client-secret": "s1", "redirect-uris": "https://example.test/cb",
		}),
		authClientSecretNamed("ns", "two", map[string]string{
			"client-id": "two", "client-secret": "s2", "redirect-uris": "https://example.test/cb",
		}),
	}
	clients, err := AuthClientLoader(secrets)
	require.NoError(t, err)
	assert.Len(t, clients, 2)
}

// TestAuthClientLoaderRejectsDisagreeingAliases pins the second half of #297.
//
// Every field accepts an underscore and a hyphenated spelling. The underscore
// form wins unconditionally and nothing says so, so a Secret carrying
// client_secret: <old> and client-secret: <new> (the natural result of adding
// the "new" key beside the old one) reads as unchanged forever.
//
// Two spellings that agree are harmless and must keep loading; two that differ
// are an ambiguity only the operator can resolve, so fail closed rather than
// pick silently.
func TestAuthClientLoaderRejectsDisagreeingAliases(t *testing.T) {
	for name, data := range map[string]map[string]string{
		"client secret": {
			"client-id":     "c",
			"client_secret": "old",
			"client-secret": "new",
			"redirect-uris": "https://example.test/cb",
		},
		"client id": {
			"client_id":     "a",
			"client-id":     "b",
			"client-secret": "s3cret",
			"redirect-uris": "https://example.test/cb",
		},
		"redirect uris": {
			"client-id":     "c",
			"client-secret": "s3cret",
			"redirect_uris": "https://example.test/old",
			"redirect-uris": "https://example.test/new",
		},
		"allowed grant types": {
			"client-id":           "c",
			"client-secret":       "s3cret",
			"redirect-uris":       "https://example.test/cb",
			"allowed_grant_types": "client_credentials",
			"allowed-grant-types": "refresh_token",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := AuthClientLoader(kdexv1alpha1.Secrets{
				authClientSecretNamed("ns", "shadowed", data),
			})
			require.Error(t, err, "two different values under one field's two spellings must not load")
			assert.Contains(t, err.Error(), "shadowed",
				"the error must name the Secret that carries the ambiguity")
		})
	}
}

// TestAuthClientLoaderAcceptsAgreeingAliases proves the guard above only fires
// on disagreement: a Secret that carries both spellings with the same value
// (harmless, and what a client-side apply can produce) must still load.
func TestAuthClientLoaderAcceptsAgreeingAliases(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id":      "c",
		"client-id":      "c",
		"client_secret":  "s3cret",
		"client-secret":  "s3cret",
		"redirect_uris":  "https://example.test/cb",
		"redirect-uris":  "https://example.test/cb",
		"allowed_scopes": "openid",
		"allowed-scopes": "openid",
	})}
	clients, err := AuthClientLoader(secrets)
	require.NoError(t, err)
	require.Contains(t, clients, "c")
	assert.Equal(t, "s3cret", clients["c"].ClientSecret)
	assert.Equal(t, []string{"https://example.test/cb"}, clients["c"].RedirectURIs)
}

// TestAuthClientLoaderRecordsSource proves each static client remembers which
// Secret supplied it, so a failed client authentication can say which object
// was consulted. Without it the token endpoint's log cannot distinguish "the
// caller presented a stale secret" from "a shadowed key won" from "another
// Secret owns this id".
func TestAuthClientLoaderRecordsSource(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{
		authClientSecretNamed("spike2", "troubleshooting-spike2", map[string]string{
			"client-id":     "troubleshooting-spike2",
			"client-secret": "s3cret",
			"redirect-uris": "https://example.test/cb",
		}),
	}
	clients, err := AuthClientLoader(secrets)
	require.NoError(t, err)
	assert.Equal(t, "spike2/troubleshooting-spike2", clients["troubleshooting-spike2"].Source)
}

// TestAuthClientLoaderRejectsEmptyClientID pins the guard from
// kdex-tech/host-manager#173.
//
// A client authored with no client_id loads under the "" key. There is no
// live path to it from the token endpoint today — a caller cannot present
// client_id="" because LookupClient(ctx, "") must succeed first — but the ""-keyed
// entry is a bridge to the cookie-path grace records, which are the records
// minted with ClientID: "". A public client authored with no id would
// therefore become reachable by exactly the client-binding check #169 added
// to keep a rotated refresh token away from a caller that never owned the
// session.
//
// Fail closed at load time rather than carry an entry whose only consumer is
// a bug.
func TestAuthClientLoaderRejectsEmptyClientID(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_secret": "s3cret",
		"redirect_uris": "https://example.test/callback",
	})}

	if _, err := AuthClientLoader(secrets); err == nil {
		t.Fatal("expected an error for an auth-client secret with no client_id")
	} else if !strings.Contains(err.Error(), "client_id") {
		t.Fatalf("error should name client_id so an operator can find the offending secret, got: %v", err)
	}
}

// TestAuthClientLoaderAcceptsNonEmptyClientID proves the guard above is
// specific to the empty id and does not reject ordinary clients.
func TestAuthClientLoaderAcceptsNonEmptyClientID(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id":     "ordinary",
		"client_secret": "s3cret",
		"redirect_uris": "https://example.test/callback",
	})}

	clients, err := AuthClientLoader(secrets)
	if err != nil {
		t.Fatalf("a client with a non-empty id must load: %v", err)
	}
	if _, ok := clients["ordinary"]; !ok {
		t.Fatalf("expected client %q to be loaded, got keys: %v", "ordinary", clients)
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

// TestAuthClientLoaderParsesAllowedResources pins the RFC 8707 resource
// indicator allowlist: a confidential client's allowed-resources Secret key
// loads into AuthClient.AllowedResources, and its absence yields an empty
// (never nil-panicking) slice rather than an error.
//
// The spec describes allowed-resources as "space/comma-separated", so a
// comma+space value must split into trimmed elements (no leading spaces
// that would silently fail the exact allowlist match in
// clientCredentialsGrant), and a purely space-separated value must split
// too.
func TestAuthClientLoaderParsesAllowedResources(t *testing.T) {
	secrets := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id":           "eum-blobsqlite",
		"client_secret":       "s3cret",
		"allowed-grant-types": "client_credentials",
		"allowed-resources":   "/db/v1, https://host.example/db/v1",
	})}
	clients, err := AuthClientLoader(secrets)
	require.NoError(t, err)
	c, ok := clients["eum-blobsqlite"]
	require.True(t, ok)
	assert.Equal(t, []string{"/db/v1", "https://host.example/db/v1"}, c.AllowedResources)

	// Space-separated (no commas) must also split.
	secretsSpace := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id":           "eum-blobsqlite-space",
		"client_secret":       "s3cret",
		"allowed-grant-types": "client_credentials",
		"allowed-resources":   "/db/v1 https://host.example/db/v1",
	})}
	clientsSpace, err := AuthClientLoader(secretsSpace)
	require.NoError(t, err)
	cSpace, ok := clientsSpace["eum-blobsqlite-space"]
	require.True(t, ok)
	assert.Equal(t, []string{"/db/v1", "https://host.example/db/v1"}, cSpace.AllowedResources)

	// Absent -> empty (not nil-panic).
	secrets2 := kdexv1alpha1.Secrets{authClientSecret(map[string]string{
		"client_id": "x", "client_secret": "y", "allowed-grant-types": "client_credentials",
	})}
	clients2, err := AuthClientLoader(secrets2)
	require.NoError(t, err)
	assert.Empty(t, clients2["x"].AllowedResources)
}
