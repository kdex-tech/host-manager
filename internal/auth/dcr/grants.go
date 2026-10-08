package dcr

import "slices"

// SupportedGrantTypes is the complete set a DYNAMICALLY REGISTERED client may
// hold. It is deliberately narrower than the authorization server's own
// grant_types_supported: those are available to statically configured clients,
// which an operator authored and can be held accountable for, whereas a DCR
// client is anonymous, credential-less and freely re-mintable.
//
// Keep this a redirect-based pair. Adding a grant that authenticates without a
// redirect (password, client_credentials) hands an unauthenticated caller a
// working credential-testing client. See GHSA-hm9g-w2cw-j7gg.
var SupportedGrantTypes = []string{"authorization_code", "refresh_token"}

// FilterGrantTypes applies the DCR grant policy to a client's grants. With
// none given it returns SupportedGrantTypes (the registration default);
// otherwise it keeps only the supported ones, preserving order and dropping
// duplicates. An empty result means nothing given was supported, which every
// caller must treat as a refusal: an empty grant list reads as "every grant" at
// the token endpoint.
//
// It runs both when a client registers and when a stored client is read back,
// so a record persisted before registration filtered grants (pre-v0.5.1) is
// held to the same policy.
func FilterGrantTypes(grants []string) []string {
	if len(grants) == 0 {
		return slices.Clone(SupportedGrantTypes)
	}
	kept := make([]string, 0, len(grants))
	for _, g := range grants {
		if slices.Contains(SupportedGrantTypes, g) && !slices.Contains(kept, g) {
			kept = append(kept, g)
		}
	}
	return kept
}
