package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"slices"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	kdexv1alpha1 "kdex.dev/crds/api/v1alpha1"
)

const (
	PrivateKeySecretKey = "private-key"
)

var (
	instance *KeyPairs
	once     sync.Once
)

type KeyPair struct {
	ActiveKey bool
	KeyId     string
	Private   crypto.Signer
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

// LoadOrGenerateKeyPair loads a key pair from a Kubernetes Secret.
// If the secret doesn't exist or is invalid, it generates a new key pair.
func LoadOrGenerateKeyPair(
	secrets kdexv1alpha1.ServiceAccountSecrets,
	devMode bool,
) (*KeyPairs, error) {
	filtered := secrets.Filter(func(s corev1.Secret) bool {
		return s.Annotations["kdex.dev/secret-type"] == "jwt-keys"
	})

	// reverse sort by creation timestamp
	slices.SortFunc(filtered, func(a, b corev1.Secret) int {
		// Sort to Ascending - oldest to newest
		return a.CreationTimestamp.Compare(b.CreationTimestamp.Time)
	})

	pairs := &KeyPairs{}
	found := false

	// The newest secret with the active key annotation is the active key. If no
	// active key annotation is found, the newest secret is the active key.
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

		return pairs, nil
	}

	if devMode {
		return GenerateECDSAKeyPair(), nil
	}

	return nil, nil
}

// GenerateECDSAKeyPair generates a new ECDSA key pair for JWT signing.
func GenerateECDSAKeyPair() *KeyPairs {
	once.Do(func() {
		// 1. Use P-256 (ES256). It's lightning fast for dev restarts.
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			// Panic because if we can't get entropy, we can't secure anything.
			panic(err)
		}

		// 2. Generate a unique ID based on the startup time.
		// This ensures clients/verifiers don't use a cached public key
		// from a previous process run.
		kid := fmt.Sprintf("kdex-dev-%d", time.Now().Unix())

		instance = &KeyPairs{
			{
				ActiveKey: true,
				KeyId:     kid,
				Private:   privateKey,
			},
		}
	})
	return instance
}

func GenerateRSAKeyPair() *KeyPairs {
	once.Do(func() {
		// 1. Generate a 2048-bit RSA key.
		// Note: RSA generation is mathematically more intensive than ECDSA
		// and may take a few hundred milliseconds.
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			// Panic because entropy is critical for RSA prime generation.
			panic(fmt.Errorf("failed to generate RSA key: %w", err))
		}

		// 2. Generate a unique ID based on the startup time.
		kid := fmt.Sprintf("kdex-rsa-dev-%d", time.Now().Unix())

		instance = &KeyPairs{
			{
				ActiveKey: true,
				KeyId:     kid,
				Private:   privateKey,
			},
		}
	})
	return instance
}

// LoadKeyFromPEM loads a private key from a PEM encoded private key.
func LoadKeyFromPEM(privateKeyPEM []byte) (*KeyPair, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	var privKey any
	var err error

	// Try PKCS8 first (Modern standard, supports both RSA and ECDSA)
	privKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback to PKCS1 (RSA Specific)
		privKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Fallback to SEC1 (EC Specific)
			privKey, err = x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key in any format: %w", err)
			}
		}
	}

	// Ensure it's a type that we support
	switch privKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		// Valid keys
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privKey)
	}

	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key type %T does not implement crypto.Signer", privKey)
	}

	kid, ok := block.Headers["KID"]
	if ok {
		return &KeyPair{Private: signer, KeyId: kid}, nil
	}

	return &KeyPair{Private: signer}, nil
}

// LoadKeysFromSecret loads an key pair from a Kubernetes Secret.
func LoadKeysFromSecret(secret *corev1.Secret, isActive bool) (*KeyPair, error) {
	privateKeyPEM, ok := secret.Data[PrivateKeySecretKey]
	if !ok {
		return nil, fmt.Errorf("secret does not contain %s", PrivateKeySecretKey)
	}

	keyPair, err := LoadKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, err
	}

	if keyPair.KeyId == "" {
		keyPair.KeyId = secret.Name
	}

	keyPair.ActiveKey = isActive

	return keyPair, nil
}
