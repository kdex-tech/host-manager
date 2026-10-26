package auth

import (
	"context"
	"time"
)

// CredentialPredatesRevocation reports whether ac's credential authenticated
// its subject at or before that subject was revoked on this host
// (/-/apitokens/revoke with all). Such a credential must not issue a new one
// -- an API key, a capability token, an authorization code -- or a live
// session would outlast the cutoff and hand what it mints to a re-signup.
// See kdex-tech/host-manager#257.
//
// A credential with no issue time counts as authenticated before it. Issue
// times are whole seconds, so a fresh authentication in the same second as
// the revocation is refused too: it fails closed, and a retry a second later
// succeeds. A revocation store that cannot be read is an error, never a no.
func (c *Config) CredentialPredatesRevocation(ctx context.Context, ac AuthContext) (bool, error) {
	if c == nil || c.TokenManager == nil {
		return false, nil
	}
	sub, _ := ac.GetSubject()
	if sub == "" {
		return false, nil
	}
	issuedAt := time.Time{}
	if iat, err := ac.GetIssuedAt(); err == nil && iat != nil {
		issuedAt = iat.Time
	}
	return c.TokenManager.SubjectRevokedSince(ctx, sub, issuedAt)
}
