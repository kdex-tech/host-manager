package auth

import (
	"encoding/json"
	"net/http"
)

// OpenIDConfiguration represents the OIDC discovery document.
type OpenIDConfiguration struct {
	AuthorizationEndpoint            string   `json:"authorization_endpoint,omitempty"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
	GrantTypesSupported              []string `json:"grant_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	Issuer                           string   `json:"issuer"`
	JwksURI                          string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint,omitempty"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ScopesSupported                  []string `json:"scopes_supported,omitempty"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	TokenEndpoint                    string   `json:"token_endpoint,omitempty"`
}

// DiscoveryHandler creates an HTTP handler that serves the OpenID discovery document.
func DiscoveryHandler(issuer string, registrationEndpoint string) http.HandlerFunc {
	config := OpenIDConfiguration{
		AuthorizationEndpoint: issuer + "/-/oauth/authorize",
		ClaimsSupported: []string{
			"aud",
			"birthdate",
			"email",
			"entitlements",
			"exp",
			"family_name",
			"gender",
			"given_name",
			"iat",
			"iss",
			"jti",
			"locale",
			"middle_name",
			"name",
			"nickname",
			"picture",
			"preferred_username",
			"profile",
			"roles",
			"sub",
			"updated_at",
			"website",
			"zoneinfo",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"client_credentials",
			"password",
			"refresh_token",
		},
		IDTokenSigningAlgValuesSupported: []string{"RS256", "ES256"},
		Issuer:                           issuer,
		JwksURI:                          issuer + "/.well-known/jwks.json",
		ResponseTypesSupported:           []string{"code", "id_token"},
		ScopesSupported: []string{
			"email",
			"entitlements",
			"openid",
			"profile",
			"roles",
		},
		SubjectTypesSupported: []string{"public"},
		TokenEndpoint:         issuer + "/-/token",
	}
	config.CodeChallengeMethodsSupported = []string{PKCE_METHOD_S256}
	if registrationEndpoint != "" {
		config.RegistrationEndpoint = registrationEndpoint
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")

		if err := json.NewEncoder(w).Encode(config); err != nil {
			http.Error(w, "Failed to encode discovery document", http.StatusInternalServerError)
			return
		}
	}
}
