package apitoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/kdex-tech/host-manager/internal/cache"
	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var (
	instance *KeyPairs
	once     sync.Once
)

// pasetoV4PublicHeader is the fixed protocol header of every v4.public PASETO
// token produced by V4Sign. In white-label (replace) prefixing this header is
// swapped out for the host's brand prefix on the wire and restored before any
// parse, so the bytes handed to the parser are identical to what V4Sign
// produced and the signature is unaffected.
const pasetoV4PublicHeader = "v4.public."

type TokenData struct {
	Action     string `json:"act"`
	Audience   string `json:"aud"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`
	Issuer     string `json:"iss"`
	JTI        string `json:"jti"`
	KID        string `json:"kid"`
	NotBefore  int64  `json:"nbf"`
	Scope      string `json:"scp"`
	Subject    string `json:"sub"`
}

type KeyPair struct {
	ActiveKey bool
	KeyId     string
	PublicKey *paseto.V4AsymmetricPublicKey
	SecretKey *paseto.V4AsymmetricSecretKey
}

type KeyPairs []*KeyPair

func (p *KeyPairs) ActiveKey() *KeyPair {
	if p == nil {
		return nil
	}
	if len(*p) == 1 {
		return (*p)[0]
	}
	for _, pair := range *p {
		if pair.ActiveKey {
			return pair
		}
	}
	return nil
}

func (p *KeyPairs) GetKey(kid string) (*KeyPair, bool) {
	for _, pair := range *p {
		if pair.KeyId == kid {
			return pair, true
		}
	}
	return nil, false
}

type TokenManager struct {
	activeKey       KeyPair
	issuer          string
	keyPairs        KeyPairs
	revocationCache cache.Cache
	tokenPrefix     string
}

func APITokenManagerLoader(
	issuer string,
	secrets kdexv1alpha1.Secrets,
	revocationCache cache.Cache,
	devMode bool,
) (*TokenManager, error) {
	filtered := secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "api-key" })
	if !devMode && len(filtered) == 0 {
		return nil, nil
	}

	// reverse sort by creation timestamp
	slices.SortFunc(filtered, func(a, b corev1.Secret) int {
		// Sort to Ascending - oldest to newest
		return a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
	})

	pairs := &KeyPairs{}
	found := false

	for i, secret := range filtered {
		isActive := false
		if secret.Annotations["kdex.dev/active-key"] == "true" {
			isActive = true
		}

		kp, err := LoadKeysFromSecret(&secret, isActive)
		if err != nil {
			return nil, err
		}

		found = true
		*pairs = append(*pairs, kp)

		// make sure only one key is active
		if kp.ActiveKey && i > 0 {
			(*pairs)[i-1].ActiveKey = false
		}
	}

	if found {
		if len(*pairs) > 1 && pairs.ActiveKey() == nil {
			(*pairs)[len(*pairs)-1].ActiveKey = true
		}

		// If only one key, make it active if not already
		if len(*pairs) == 1 && pairs.ActiveKey() == nil {
			(*pairs)[0].ActiveKey = true
		}

		return NewTokenManager(issuer, pairs, revocationCache)
	}

	if devMode {
		return NewTokenManager(issuer, GenerateDevmodeKeyPair(), revocationCache)
	}

	return nil, nil
}

func NewTokenManager(issuer string, keyPairs *KeyPairs, revocationCache cache.Cache) (*TokenManager, error) {
	return &TokenManager{
		issuer:          issuer,
		activeKey:       *keyPairs.ActiveKey(),
		keyPairs:        *keyPairs,
		revocationCache: revocationCache,
		// tokenPrefix defaults to "" — prefixing is opt-in via WithTokenPrefix.
	}, nil
}

// WithTokenPrefix sets this host's white-label API token prefix. Prefixing is
// off by default (empty), in which case tokens are emitted as bare
// "v4.public." PASETO strings. When set, the prefix REPLACES the PASETO header
// on the wire (see wrap/unwrap). Returns the receiver for chaining. This is the
// single configuration point for the prefix; the controller sources it from
// KDexHost.spec.auth.apiToken.tokenPrefix (falling back to the
// NexusConfiguration default) and calls this once per host.
func (tm *TokenManager) WithTokenPrefix(prefix string) *TokenManager {
	tm.tokenPrefix = prefix
	return tm
}

// TokenPrefix returns this host's white-label API token prefix (empty when
// prefixing is off). Callers that need to discriminate a brand-prefixed PAT on
// the wire (e.g. the Bearer auth path) use this to recognize the prefix without
// reaching into the manager's internals.
func (tm *TokenManager) TokenPrefix() string {
	return tm.tokenPrefix
}

// wrap converts a freshly signed token to its on-the-wire form by REPLACING the
// PASETO "v4.public." header with this host's brand prefix (e.g.
// "kdex_pat_<payload>.<footer>"). No-op when no prefix is configured. Must be
// applied only AFTER signing. Because the swap is a deterministic substitution
// of a fixed header for a fixed prefix, unwrap restores the exact original
// bytes, so the signature is unaffected.
func (tm *TokenManager) wrap(signed string) string {
	if tm.tokenPrefix == "" {
		return signed
	}
	return tm.tokenPrefix + strings.TrimPrefix(signed, pasetoV4PublicHeader)
}

// unwrap restores the PASETO header on an inbound token before parsing. It is
// deliberately lenient and ordered so bare tokens are detected first: a token
// that already begins with "v4.public." (e.g. issued before prefixing was
// enabled, or sent by a client that omits the prefix) is returned unchanged;
// otherwise, if it carries this host's prefix, the prefix is swapped back to
// the header. Anything else is passed through untouched (it will fail the
// signature check downstream). Must be applied BEFORE any parse.
func (tm *TokenManager) unwrap(signed string) string {
	if tm.tokenPrefix == "" || strings.HasPrefix(signed, pasetoV4PublicHeader) {
		return signed
	}
	if rest, ok := strings.CutPrefix(signed, tm.tokenPrefix); ok {
		return pasetoV4PublicHeader + rest
	}
	return signed
}

func (tm *TokenManager) KeyPairs() KeyPairs {
	return tm.keyPairs
}

func (tm *TokenManager) RevokeByMetadata(ctx context.Context, aud, sub, act string, ttl time.Duration) error {
	if tm.revocationCache == nil {
		return fmt.Errorf("revocation cache not configured")
	}

	jti := GenerateJTI(aud, sub, act)

	return tm.revocationCache.Set(ctx, jti, "revoked", cache.WithTTL(ttl))
}

func (tm *TokenManager) RevokeToken(ctx context.Context, signed string) error {
	if tm.revocationCache == nil {
		return fmt.Errorf("revocation cache not configured")
	}

	// Strip the application-level prefix (if any) before any PASETO parsing.
	signed = tm.unwrap(signed)

	// 1. Peek at the footer to get the KID
	parser := paseto.NewParser()
	footerBytes, err := parser.UnsafeParseFooter(paseto.V4Public, signed)
	if err != nil {
		return err
	}

	var footerData struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(footerBytes, &footerData); err != nil {
		return err
	}

	// 2. Lookup the public key
	keyPair, exists := tm.keyPairs.GetKey(footerData.KID)
	if !exists {
		return fmt.Errorf("key not found: %s", footerData.KID)
	}

	// 3. Parse the token to get JTI and expiration
	// We don't use tm.ValidateToken because it might perform a revocation check
	// and we want to be able to revoke a token even if it's already revoked (idempotency).
	token, err := parser.ParseV4Public(*keyPair.PublicKey, signed, nil)
	if err != nil {
		return err
	}

	jti, err := token.GetJti()
	if err != nil {
		return err
	}

	exp, err := token.GetExpiration()
	if err != nil {
		return err
	}

	ttl := time.Until(exp)
	if ttl <= 0 {
		// Already expired, no need to revoke in cache
		return nil
	}

	return tm.revocationCache.Set(ctx, jti, "revoked", cache.WithTTL(ttl))
}

func (tm *TokenManager) MintStatelessKey(aud string, sub string, action string, scope string, ttl time.Duration) (string, error) {
	now := time.Now()
	exp := now.Add(ttl)

	token := paseto.NewToken()

	token.SetAudience(aud)
	token.SetExpiration(exp)
	token.SetIssuedAt(now)
	token.SetIssuer(tm.issuer)
	token.SetJti(GenerateJTI(aud, sub, action))
	token.SetNotBefore(now)
	token.SetSubject(sub)

	token.SetString("act", action)
	token.SetString("scp", scope)

	token.SetFooter([]byte(`{"kid":"` + tm.activeKey.KeyId + `"}`))

	signed := token.V4Sign(*tm.activeKey.SecretKey, nil)

	return tm.wrap(signed), nil
}

// ValidateToken parses and verifies a PASETO API token.
//
// expectedAudience is REQUIRED in spirit but technically optional in
// signature:
//   - non-empty: a paseto.ForAudience rule is added so a token minted
//     for a different audience is rejected. This is the correct mode
//     for any handler that uses ValidateToken's success as proof the
//     bearer should be granted access on the receiving party.
//   - empty: the audience check is skipped. This is ONLY appropriate
//     when the token is being INSPECTED (e.g. to extract its subject
//     for a revocation flow) — not when validating for use. Passing
//     "" in any other context is the kdex-tech/host-manager#69
//     confused-deputy regression.
func (tm *TokenManager) ValidateToken(ctx context.Context, signed, expectedAudience string) (*TokenData, error) {
	// Strip the application-level prefix (if any) before any PASETO parsing.
	signed = tm.unwrap(signed)

	// 1. Peek at the footer without verifying the signature
	// This is safe because the footer is always in the clear (Base64)
	parser := paseto.NewParser()
	footerBytes, err := parser.UnsafeParseFooter(paseto.V4Public, signed)
	if err != nil {
		return nil, err
	}

	// 2. Extract the KID from the JSON footer
	var footerData struct {
		KID string `json:"kid"`
	}
	if err := json.Unmarshal(footerBytes, &footerData); err != nil {
		return nil, err
	}

	// 3. Lookup the public key in your local cache
	keyPair, exists := tm.keyPairs.GetKey(footerData.KID)
	if !exists {
		return nil, fmt.Errorf("key not found: %s", footerData.KID)
	}

	parser.AddRule(paseto.IssuedBy(tm.issuer))
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))
	if expectedAudience != "" {
		parser.AddRule(paseto.ForAudience(expectedAudience))
	}

	token, err := parser.ParseV4Public(*keyPair.PublicKey, signed, nil)
	if err != nil {
		return nil, err
	}

	// 4. Revocation check
	if tm.revocationCache != nil {
		jti, err := token.GetJti()
		if err != nil {
			return nil, err
		}

		_, found, _, err := tm.revocationCache.Get(ctx, jti)
		if err != nil {
			return nil, fmt.Errorf("failed to check revocation status: %w", err)
		}
		if found {
			return nil, fmt.Errorf("token revoked")
		}
	}

	subject, err := token.GetSubject()
	if err != nil {
		return nil, err
	}

	action, err := token.GetString("act")
	if err != nil {
		return nil, err
	}

	scope, err := token.GetString("scp")
	if err != nil {
		return nil, err
	}

	audience, err := token.GetAudience()
	if err != nil {
		return nil, err
	}

	exp, err := token.GetExpiration()
	if err != nil {
		return nil, err
	}

	iat, err := token.GetIssuedAt()
	if err != nil {
		return nil, err
	}

	issuer, err := token.GetIssuer()
	if err != nil {
		return nil, err
	}

	jti, err := token.GetJti()
	if err != nil {
		return nil, err
	}

	nbf, err := token.GetNotBefore()
	if err != nil {
		return nil, err
	}

	return &TokenData{
		Audience:   audience,
		Expiration: exp.Unix(),
		IssuedAt:   iat.Unix(),
		Issuer:     issuer,
		JTI:        jti,
		KID:        footerData.KID,
		NotBefore:  nbf.Unix(),
		Subject:    subject,
		Action:     action,
		Scope:      scope,
	}, nil
}

func GenerateJTI(aud, sub, act string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", aud, sub, act)))

	return hex.EncodeToString(hash[:])
}

func GenerateKID(pubBytes []byte) string {
	hash := sha256.Sum256(pubBytes)

	return hex.EncodeToString(hash[:])[:16]
}

func GenerateDevmodeKeyPair() *KeyPairs {
	once.Do(func() {
		secretKey := paseto.NewV4AsymmetricSecretKey()

		publicKey := secretKey.Public()
		exportedBytes := publicKey.ExportBytes()

		instance = &KeyPairs{
			{
				ActiveKey: true,
				KeyId:     GenerateKID(exportedBytes),
				PublicKey: &publicKey,
				SecretKey: &secretKey,
			},
		}
	})
	return instance
}

// LoadKeysFromSecret loads an key pair from a Kubernetes Secret.
func LoadKeysFromSecret(secret *corev1.Secret, isActive bool) (*KeyPair, error) {
	privateKeyBytes, ok := secret.Data["private-key"]
	if !ok || len(privateKeyBytes) == 0 {
		return nil, fmt.Errorf("private-key is required")
	}

	secretKey, err := paseto.NewV4AsymmetricSecretKeyFromBytes(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	publicKey := secretKey.Public()
	exportedBytes := publicKey.ExportBytes()
	publicKeyBytes, ok := secret.Data["public-key"]

	if ok {
		if !bytes.Equal(exportedBytes, publicKeyBytes) {
			return nil, fmt.Errorf("public key %x does not match argument %x", exportedBytes, publicKeyBytes)
		}
	}

	keyPair := &KeyPair{
		KeyId:     GenerateKID(exportedBytes),
		PublicKey: &publicKey,
		SecretKey: &secretKey,
	}

	keyPair.ActiveKey = isActive

	return keyPair, nil
}
