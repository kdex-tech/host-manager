package auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
)

// Seal purposes. Each derives its own key from the OIDC block key, so a value
// sealed for one use can never be opened as another. Authorization codes keep
// the unlabelled legacy key so codes in flight survive the rollout.
const (
	sealPurposeAuthCode   = ""
	sealPurposeLoginState = "oidc-login-state"
	sealPurposeConsent    = "dcr-consent"
)

var (
	errSealParse   = errors.New("sealed value is malformed")
	errSealDecrypt = errors.New("sealed value does not open with this key")
)

func (e *Exchanger) sealKey(purpose string) []byte {
	var sum [32]byte
	if purpose == sealPurposeAuthCode {
		sum = sha256.Sum256([]byte(e.config.OIDC.BlockKey))
	} else {
		sum = sha256.Sum256([]byte(purpose + "\x00" + e.config.OIDC.BlockKey))
	}
	return sum[:]
}

// seal encrypts payload as a compact JWE (dir + A256GCM) under purpose's key.
func (e *Exchanger) seal(purpose string, payload []byte) (string, error) {
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.DIRECT, Key: e.sealKey(purpose)}, nil)
	if err != nil {
		return "", err
	}
	obj, err := enc.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// open reverses seal. Its errors wrap errSealParse or errSealDecrypt and carry
// the library's cause only after the sentinel, so callers can choose what to
// show a client.
func (e *Exchanger) open(purpose, sealed string) ([]byte, error) {
	obj, err := jose.ParseEncrypted(sealed, []jose.KeyAlgorithm{jose.DIRECT}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSealParse, err)
	}
	payload, err := obj.Decrypt(e.sealKey(purpose))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSealDecrypt, err)
	}
	return payload, nil
}

func (e *Exchanger) sealJSON(purpose string, v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return e.seal(purpose, payload)
}

func (e *Exchanger) openJSON(purpose, sealed string, v any) error {
	payload, err := e.open(purpose, sealed)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, v)
}
