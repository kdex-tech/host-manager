package apitoken

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/google/uuid"

	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

var (
	instance *KeyPairs
	once     sync.Once
)

type TokenData struct {
	Action  string
	Scope   string
	Subject string
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
	activeKey    KeyPair
	apiKeyIssuer string
	keyPairs     KeyPairs
}

func APITokenManagerLoader(
	issuer string,
	secrets kdexv1alpha1.ServiceAccountSecrets,
	devMode bool,
) (*TokenManager, error) {
	filtered := secrets.Filter(func(s corev1.Secret) bool { return s.Annotations["kdex.dev/secret-type"] == "api-key" })
	if len(filtered) == 0 {
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

		return NewTokenManager(issuer, pairs)
	}

	if devMode {
		return NewTokenManager(issuer, GenerateDevmodeKeyPair())
	}

	return nil, nil
}

func NewTokenManager(apiKeyIssuer string, keyPairs *KeyPairs) (*TokenManager, error) {
	return &TokenManager{
		apiKeyIssuer: apiKeyIssuer,
		activeKey:    *keyPairs.ActiveKey(),
		keyPairs:     *keyPairs,
	}, nil
}

func (tm *TokenManager) KeyPairs() KeyPairs {
	return tm.keyPairs
}

func (tm *TokenManager) MintStatelessKey(aud string, sub string, action string, scope string, ttl time.Duration) (string, error) {
	now := time.Now()
	exp := now.Add(ttl)

	token := paseto.NewToken()

	token.SetAudience(aud)
	token.SetExpiration(exp)
	token.SetIssuedAt(now)
	token.SetIssuer(tm.apiKeyIssuer)
	token.SetJti(uuid.New().String())
	token.SetNotBefore(now)
	token.SetSubject(sub)

	token.SetString("act", action)
	token.SetString("scp", scope)

	token.SetFooter([]byte(`{"kid":"` + tm.activeKey.KeyId + `"}`))

	signed := token.V4Sign(*tm.activeKey.SecretKey, nil)

	return signed, nil
}

func (tm *TokenManager) ValidateToken(signed string) (*TokenData, error) {
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

	parser.AddRule(paseto.IssuedBy(tm.apiKeyIssuer))
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	token, err := parser.ParseV4Public(*keyPair.PublicKey, signed, nil)
	if err != nil {
		return nil, err
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

	return &TokenData{
		Action:  action,
		Scope:   scope,
		Subject: subject,
	}, nil
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
