package auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"

	"github.com/kdex-tech/host-manager/internal/keys"
)

// JWK represents a JSON Web Key.
type JWK struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Use string `json:"use"`
	// RSA fields
	E string `json:"e,omitempty"`
	N string `json:"n,omitempty"`
	// ECDSA fields
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKSet represents a JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// JWKSHandler creates an HTTP handler that serves the JWKS endpoint.
// This endpoint exposes the public key(s) used to verify JWT signatures.
func JWKSHandler(keyPairs *keys.KeyPairs) http.HandlerFunc {
	keyList := make([]JWK, 0, len(*keyPairs))

	for _, pair := range *keyPairs {
		pub := pair.Private.Public()

		// Base JWK info
		item := JWK{
			Use: "sig",
			Kid: pair.KeyId,
		}

		switch v := pub.(type) {
		case *rsa.PublicKey:
			item.Kty = "RSA"
			item.Alg = "RS256"
			item.N = base64.RawURLEncoding.EncodeToString(v.N.Bytes())
			item.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(v.E)).Bytes())

		case *ecdsa.PublicKey:
			item.Kty = "EC"
			item.Alg = "ES256"
			item.Crv = v.Curve.Params().Name

			// Get the uncompressed bytes (0x04 || X || Y)
			pubBytes, err := v.Bytes()
			if err != nil {
				panic(err)
			}

			// The first byte is the uncompressed point indicator (0x04)
			// The rest is X and Y concatenated, each taking up half the remaining space
			coords := pubBytes[1:]
			mid := len(coords) / 2

			item.X = base64.RawURLEncoding.EncodeToString(coords[:mid])
			item.Y = base64.RawURLEncoding.EncodeToString(coords[mid:])
		}

		keyList = append(keyList, item)
	}

	jwks := JWKSet{
		Keys: keyList,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Cache-Control, ETag and the 304 belong to the caller
		// (HostHandler's jwks route), which revalidates on every reuse so a
		// rotated key is seen on the next fetch (#305).
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			http.Error(w, "Failed to encode JWKS", http.StatusInternalServerError)
			return
		}
	}
}
