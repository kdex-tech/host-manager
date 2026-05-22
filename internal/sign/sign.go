package sign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"maps"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/kdex-tech/dmapper"
)

type Signer struct {
	audience   string
	duration   time.Duration
	issuer     string
	privateKey *crypto.Signer
	kid        string
	mapper     *dmapper.Mapper
}

// NewSigner creates a new signer.
func NewSigner(
	audience string,
	duration time.Duration,
	issuer string,
	privateKey *crypto.Signer,
	kid string,
	mapper *dmapper.Mapper,
) (*Signer, error) {
	if audience == "" {
		return nil, fmt.Errorf("signer requires an audience")
	}
	if duration == 0 {
		return nil, fmt.Errorf("signer requires a duration")
	}
	if issuer == "" {
		return nil, fmt.Errorf("signer requires an issuer")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("signer requires a private key")
	}
	if kid == "" {
		return nil, fmt.Errorf("signer requires a key id")
	}
	return &Signer{
		audience:   audience,
		duration:   duration,
		issuer:     issuer,
		privateKey: privateKey,
		kid:        kid,
		mapper:     mapper,
	}, nil
}

// Sign creates a signed JWT derived from the inbound claims.
func (s *Signer) Sign(signingContext jwt.MapClaims) (string, error) {
	sub, err := signingContext.GetSubject()
	if err != nil {
		return "", fmt.Errorf("failed to get subject from claims: %w", err)
	}

	// The signer's audience is the AUTHORITATIVE outbound aud: Sign is always
	// called to re-issue a token for a SPECIFIC downstream target (the
	// per-function FAT path in proxy.go), and re-using the inbound aud would
	// make the issued token transferable to a different audience than the
	// signer was configured for. Concretely: a user logs in at the host
	// (aud=["https://<host>"]) and then calls a function; proxy.go builds a
	// signer with audience=fn.Status.URL, but the previous logic reused the
	// inbound host aud, so the function rejected the FAT with "token has
	// invalid audience". Always use s.audience.

	outboundClaims := jwt.MapClaims{
		// registered claims
		"sub": sub,
		"iss": s.issuer,
		"aud": []string{s.audience},
		"exp": time.Now().Add(s.duration).Unix(),
		"iat": time.Now().Unix(),
		"jti": rand.Text(),
	}

	// custom claims

	if email, ok := signingContext["email"]; ok {
		outboundClaims["email"] = email
	}

	if entitlements, ok := signingContext["entitlements"]; ok {
		outboundClaims["entitlements"] = entitlements
	}

	idp, hasIdp := signingContext["idp"]
	if hasIdp {
		outboundClaims["idp"] = idp
	}

	if roles, ok := signingContext["roles"]; ok {
		outboundClaims["roles"] = roles
	}

	if scope, ok := signingContext["scope"]; ok {
		outboundClaims["scope"] = scope
	}

	if grantType, ok := signingContext["grant_type"]; ok {
		outboundClaims["grant_type"] = grantType
	}

	// profile claims
	profileClaims := []string{
		"birthdate",
		"family_name",
		"gender",
		"given_name",
		"locale",
		"middle_name",
		"name",
		"nickname",
		"picture",
		"preferred_username",
		"profile",
		"updated_at",
		"website",
		"zoneinfo",
	}
	for _, claim := range profileClaims {
		if val, ok := signingContext[claim]; ok {
			outboundClaims[claim] = val
		}
	}

	if s.mapper != nil {
		extra, err := s.mapper.Execute(signingContext)
		if err != nil {
			return "", fmt.Errorf("failed to map claims: %w", err)
		}

		maps.Copy(outboundClaims, extra)
	}

	var method jwt.SigningMethod

	// Check the public key type to decide the signing algorithm
	switch (*s.privateKey).Public().(type) {
	case *rsa.PublicKey:
		method = jwt.SigningMethodRS256
	case *ecdsa.PublicKey:
		method = jwt.SigningMethodES256
	default:
		return "", fmt.Errorf("unsupported signer type")
	}

	token := jwt.NewWithClaims(method, outboundClaims)
	token.Header["alg"] = method.Alg()
	token.Header["kid"] = s.kid
	token.Header["typ"] = "JWT"
	return token.SignedString(*s.privateKey)
}
