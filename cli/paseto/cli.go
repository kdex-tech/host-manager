package main

import (
	"encoding/base64"
	"fmt"

	"aidanwoods.dev/go-paseto"
)

func main() {
	secretKey := paseto.NewV4AsymmetricSecretKey()

	publicKey := secretKey.Public()

	fmt.Println("--- PASETO V4 ASYMMETRIC KEYS (PASERK) ---")
	privBytes := secretKey.ExportBytes()
	pubBytes := publicKey.ExportBytes()

	privPaserk := "k4.secret." + base64.RawURLEncoding.EncodeToString(privBytes)
	pubPaserk := "k4.public." + base64.RawURLEncoding.EncodeToString(pubBytes)

	// Test loading the generated string back into the library
	_, err := paseto.NewV4AsymmetricSecretKeyFromBytes(privBytes)
	if err != nil {
		panic("Generation failed: " + err.Error())
	}

	fmt.Printf("Private Key (for Secret): %s\n", privPaserk)
	fmt.Printf("Public Key (for .well-known): %s\n", pubPaserk)
}
