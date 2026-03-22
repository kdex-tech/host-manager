package auth

import (
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

func AuthClientLoader(secrets kdexv1alpha1.Secrets) (map[string]AuthClient, error) {
	clients := make(map[string]AuthClient)

	authClientSecrets := secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "auth-client" })

	for _, secret := range authClientSecrets {
		clientID := string(secret.Data["client_id"])
		if clientID == "" {
			clientID = string(secret.Data["client-id"])
		}

		clientSecret := string(secret.Data["client_secret"])
		if clientSecret == "" {
			clientSecret = string(secret.Data["client-secret"])
		}

		public := false
		if string(secret.Data["public"]) == TRUE {
			public = true
		}

		if !public && clientSecret == "" {
			return nil, fmt.Errorf("client %s is not public but has no client secret", clientID)
		}

		redirectURIsStr := string(secret.Data["redirect_uris"])
		if redirectURIsStr == "" {
			redirectURIsStr = string(secret.Data["redirect-uris"])
		}

		redirectURIs := []string{}
		if redirectURIsStr != "" {
			redirectURIs = strings.Split(redirectURIsStr, ",")
		}

		allowedGrantTypesStr := string(secret.Data["allowed_grant_types"])
		if allowedGrantTypesStr == "" {
			allowedGrantTypesStr = string(secret.Data["allowed-grant-types"])
		}
		allowedGrantTypes := []string{}
		if allowedGrantTypesStr != "" {
			allowedGrantTypes = strings.Split(allowedGrantTypesStr, ",")
		}

		allowedScopesStr := string(secret.Data["allowed_scopes"])
		if allowedScopesStr == "" {
			allowedScopesStr = string(secret.Data["allowed-scopes"])
		}
		allowedScopes := []string{}
		if allowedScopesStr != "" {
			allowedScopes = strings.Split(allowedScopesStr, ",")
		}

		description := string(secret.Data["description"])
		name := string(secret.Data["name"])

		requirePKCE := false
		if string(secret.Data["require_pkce"]) == TRUE || string(secret.Data["require-pkce"]) == TRUE {
			requirePKCE = true
		}

		client := AuthClient{
			AllowedGrantTypes: allowedGrantTypes,
			AllowedScopes:     allowedScopes,
			ClientID:          clientID,
			ClientSecret:      clientSecret,
			Description:       description,
			Name:              name,
			Public:            public,
			RedirectURIs:      redirectURIs,
			RequirePKCE:       requirePKCE,
		}

		clients[clientID] = client
	}

	return clients, nil
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

	clientSecret := string(oidcSecret.Data["client_secret"])
	if clientSecret == "" {
		clientSecret = string(oidcSecret.Data["client-secret"])
	}

	if clientSecret == "" {
		return nil, fmt.Errorf("OIDC secret does not contain 'client_secret' or 'client-secret'")
	}

	clientID := string(oidcSecret.Data["client_id"])
	if clientID == "" {
		clientID = string(oidcSecret.Data["client-id"])
	}

	if clientID == "" {
		return nil, fmt.Errorf("OIDC secret does not contain 'client_id' or 'client-id'")
	}

	blockKey := string(oidcSecret.Data["block_key"])
	if blockKey == "" {
		blockKey = string(oidcSecret.Data["block-key"])
	}

	if blockKey == "" && !devMode {
		return nil, fmt.Errorf("a 'block_key' or 'block-key' was not found in the OIDC secret, generating a new one is not supported in production")
	}

	name := string(oidcSecret.Data["name"])

	return &OIDCClientConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		BlockKey:     blockKey,
		Name:         name,
	}, nil
}
