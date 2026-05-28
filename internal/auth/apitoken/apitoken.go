package apitoken

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
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
	}, nil
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

	return signed, nil
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
