package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/kdex-tech/host-manager/internal/keys"
)

func main() {
	// 1. Generate the RSA keypair using your function
	keyPairs := keys.GenerateRSAKeyPair()
	activeKeyPair := (*keyPairs)[0]

	// 2. Assert the key is RSA (since Private is a crypto.Signer interface)
	rsaPriv, ok := activeKeyPair.Private.(*rsa.PrivateKey)
	if !ok {
		panic("Key is not an RSA private key")
	}

	// 3. Convert to PKCS#1 DER bytes (Standard for RSA)
	// This creates the "BEGIN RSA PRIVATE KEY" format
	derBytes := x509.MarshalPKCS1PrivateKey(rsaPriv)

	// 4. Encode to PEM string
	block := &pem.Block{
		Bytes: derBytes,
		Headers: map[string]string{
			"KID": activeKeyPair.KeyId,
		},
		Type: "RSA PRIVATE KEY",
	}

	pemString := string(pem.EncodeToMemory(block))

	// 5. Print to console for easy copy-pasting into your test mock
	fmt.Println("--- COPY THIS RSA PRIVATE KEY ---")
	fmt.Println(pemString)
	fmt.Printf("KID for this key: %s\n", activeKeyPair.KeyId)
}
