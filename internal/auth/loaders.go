package auth

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"unicode"

	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func AuthClientLoader(secrets kdexv1alpha1.Secrets) (map[string]AuthClient, error) {
	clients := make(map[string]AuthClient)
	// owners records which Secret supplied each id so a second Secret claiming
	// it can be rejected by name. Last-one-wins is not a tie-break an operator
	// can reason about: it depends on list order, so the effective credential
	// can also change between reconciles. See kdex-tech/host-manager#297.
	owners := make(map[string]string)

	authClientSecrets := secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "auth-client" })

	for _, secret := range authClientSecrets {
		clientID, err := aliasValue(secret, "client_id", "client-id")
		if err != nil {
			return nil, err
		}

		// Fail closed on an id-less client rather than load it under the ""
		// key. Nothing reaches a ""-keyed client from the token endpoint
		// today (a caller cannot present client_id="" because LookupClient(ctx, "")
		// must succeed first), but "" is the ClientID the cookie path mints
		// its grace records with — so an id-less entry here is a bridge
		// straight past the client binding #169 added to keep a rotated
		// refresh token away from a caller that never owned the session.
		// See kdex-tech/host-manager#173.
		if clientID == "" {
			return nil, fmt.Errorf("auth-client secret %q has no client_id", secretRef(secret))
		}

		// Fail closed on a duplicate client id. The two Secrets disagree about
		// one client's credential, redirects and grants, and nothing else in
		// the system can say which one the token endpoint is checking: the
		// loser is silently inert, so rotating it "does nothing" and a leaked
		// secret keeps authenticating. Name both objects — an operator cannot
		// act on "invalid client_secret". See kdex-tech/host-manager#297.
		if owner, ok := owners[clientID]; ok && owner != secretRef(secret) {
			return nil, fmt.Errorf(
				"auth-client %q is declared by two Secrets, %q and %q: exactly one Secret may own a client id, "+
					"because the loader keeps one and silently discards the other",
				clientID, owner, secretRef(secret))
		}
		owners[clientID] = secretRef(secret)

		clientSecret, err := aliasValue(secret, "client_secret", "client-secret")
		if err != nil {
			return nil, err
		}

		public := false
		if string(secret.Data["public"]) == TRUE {
			public = true
		}

		if !public && clientSecret == "" {
			return nil, fmt.Errorf("client %s (secret %q) is not public but has no client secret", clientID, secretRef(secret))
		}

		redirectURIsStr, err := aliasValue(secret, "redirect_uris", "redirect-uris")
		if err != nil {
			return nil, err
		}

		redirectURIs := []string{}
		if redirectURIsStr != "" {
			redirectURIs = strings.Split(redirectURIsStr, ",")
		}

		allowedGrantTypesStr, err := aliasValue(secret, "allowed_grant_types", "allowed-grant-types")
		if err != nil {
			return nil, err
		}
		allowedGrantTypes := []string{}
		if allowedGrantTypesStr != "" {
			allowedGrantTypes = strings.Split(allowedGrantTypesStr, ",")
		}

		allowedScopesStr, err := aliasValue(secret, "allowed_scopes", "allowed-scopes")
		if err != nil {
			return nil, err
		}
		allowedScopes := []string{}
		if allowedScopesStr != "" {
			allowedScopes = strings.Split(allowedScopesStr, ",")
		}

		allowedResourcesStr, err := aliasValue(secret, "allowed_resources", "allowed-resources")
		if err != nil {
			return nil, err
		}
		// Spec: "space/comma-separated" -- split on either, dropping empty
		// elements (and thus any surrounding whitespace around commas) so
		// a value like "/db/v1, /other/v1" doesn't silently produce a
		// leading-space element that never matches the exact allowlist
		// check in clientCredentialsGrant.
		allowedResources := []string{}
		if allowedResourcesStr != "" {
			allowedResources = strings.FieldsFunc(allowedResourcesStr, func(r rune) bool {
				return r == ',' || unicode.IsSpace(r)
			})
		}

		description := string(secret.Data["description"])
		name := string(secret.Data["name"])

		// require_pkce/require-pkce used to be OR-ed, so "false" in one spelling
		// and "true" in the other loaded as enabled with nothing said. Treat it
		// like every other alias pair: two spellings that disagree are an
		// ambiguity to report, not a value to guess.
		requirePKCEStr, err := aliasValue(secret, "require_pkce", "require-pkce")
		if err != nil {
			return nil, err
		}
		requirePKCE := requirePKCEStr == TRUE

		// Footgun guard: a public client whose redirect uses an RFC 8252
		// private-use (custom) URI scheme is open to authorization-code
		// interception via scheme hijacking unless the code is PKCE-bound.
		// DCR-registered clients are forced RequirePKCE, but static clients
		// opt into PKCE via require_pkce — so fail closed when a public,
		// custom-scheme client omits it rather than silently load it.
		// See kdex-tech/host-manager#128.
		if public && !requirePKCE {
			for _, ru := range redirectURIs {
				if isPrivateUseScheme(ru) {
					return nil, fmt.Errorf(
						"auth-client %q is public with a private-use redirect URI %q but require_pkce is not set: "+
							"custom-scheme redirects are vulnerable to authorization-code interception without PKCE "+
							"(RFC 8252 §8.1); set require_pkce=true to allow this client",
						clientID, ru)
				}
			}
		}

		client := AuthClient{
			AllowedGrantTypes: allowedGrantTypes,
			AllowedScopes:     allowedScopes,
			AllowedResources:  allowedResources,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			Description:       description,
			Name:              name,
			Public:            public,
			RedirectURIs:      redirectURIs,
			RequirePKCE:       requirePKCE,
			Source:            secretRef(secret),
		}

		clients[clientID] = client
	}

	return clients, nil
}

// secretRef names a Secret the way an operator resolves it with kubectl:
// namespace/name when the namespace is known, the bare name otherwise. Errors
// that ask someone to fix an object must carry this, because "auth-client" or a
// client id alone does not say which of several similarly named Secrets to
// look at.
func secretRef(s corev1.Secret) string {
	if s.Namespace == "" {
		return s.Name
	}
	return s.Namespace + "/" + s.Name
}

// aliasValue reads a Secret field that may be spelled with underscores or with
// hyphens (client_id / client-id, redirect_uris / redirect-uris, ...).
//
// One spelling always won silently: the underscore form was read first and the
// hyphenated one consulted only when it was empty. A Secret carrying
// client_secret: <old> beside a freshly added client-secret: <new> therefore
// loaded the OLD credential forever, and the only symptom was the token
// endpoint answering "invalid client_secret" while the host log said
// client_secret_present=true — indistinguishable from a client that simply
// presents the wrong password. See kdex-tech/host-manager#297.
//
// Two spellings that agree are harmless and load. Two that disagree are an
// ambiguity only the operator can resolve, so this fails closed and names both
// keys rather than guessing which one was meant.
func aliasValue(s corev1.Secret, underscore, hyphen string) (string, error) {
	u, h := s.Data[underscore], s.Data[hyphen]
	switch {
	case len(u) == 0:
		return string(h), nil
	case len(h) == 0:
		return string(u), nil
	case !bytes.Equal(u, h):
		return "", fmt.Errorf(
			"secret %q sets both %q and %q to different values: keep one spelling, "+
				"because which one applies is otherwise decided silently",
			secretRef(s), underscore, hyphen)
	}
	return string(u), nil
}

// isPrivateUseScheme reports whether a redirect URI uses an RFC 8252 §7.1
// private-use (custom) URI scheme — any scheme that is neither http nor https.
// It is intentionally broader than the registration-time reverse-DNS check
// (register.go): for the footgun guard, ANY non-web scheme on a public,
// non-PKCE client is unsafe, dotted or not.
func isPrivateUseScheme(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme != "" && u.Scheme != HTTP && u.Scheme != HTTPS
}

type OIDCClientConfig struct {
	ClientID     string
	ClientSecret string
	BlockKey     string
	Name         string
}

func OIDCConfigLoader(secrets kdexv1alpha1.Secrets, devMode bool) (*OIDCClientConfig, error) {
	oidcSecret := secrets.Find(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "oidc-client" })
	if oidcSecret == nil {
		return nil, fmt.Errorf("missing secret of type 'oidc-client' required for OIDC provider")
	}

	// Same silent alias precedence as auth-client secrets, and the same reason
	// to refuse it: a shadowed block_key leaves the old key decrypting login
	// state with nothing in the system saying so. See
	// kdex-tech/host-manager#297.
	clientSecret, err := aliasValue(*oidcSecret, "client_secret", "client-secret")
	if err != nil {
		return nil, err
	}

	if clientSecret == "" {
		return nil, fmt.Errorf("OIDC secret %q does not contain 'client_secret' or 'client-secret'", secretRef(*oidcSecret))
	}

	clientID, err := aliasValue(*oidcSecret, "client_id", "client-id")
	if err != nil {
		return nil, err
	}

	if clientID == "" {
		return nil, fmt.Errorf("OIDC secret %q does not contain 'client_id' or 'client-id'", secretRef(*oidcSecret))
	}

	blockKey, err := aliasValue(*oidcSecret, "block_key", "block-key")
	if err != nil {
		return nil, err
	}

	if blockKey == "" && !devMode {
		return nil, fmt.Errorf("a 'block_key' or 'block-key' was not found in OIDC secret %q, generating a new one is not supported in production", secretRef(*oidcSecret))
	}

	name := string(oidcSecret.Data["name"])

	return &OIDCClientConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		BlockKey:     blockKey,
		Name:         name,
	}, nil
}
