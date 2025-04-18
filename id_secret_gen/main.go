package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/google/uuid" // Recommended for Client IDs
)

// GenerateClientID creates a new, unique client ID.
// Using UUID v4 is a common and reliable approach.
func GenerateClientID() (string, error) {
	id, err := uuid.NewRandom() // Generates a random UUID (version 4)
	if err != nil {
		return "", fmt.Errorf("failed to generate client ID: %w", err)
	}
	return id.String(), nil
}

// GenerateClientSecret creates a secure, random client secret.
// length specifies the number of random bytes to generate.
// A length of 32 bytes is a good starting point (results in a ~44 char Base64 string).
// A length of 64 bytes is even stronger (results in a ~86 char Base64 string).
func GenerateClientSecret(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}
	// Create a byte slice to hold the random data
	randomBytes := make([]byte, length)

	// Read cryptographically secure random bytes into the slice.
	// crypto/rand is crucial here, do NOT use math/rand.
	_, err := rand.Read(randomBytes)
	if err != nil {
		// This is a critical error, often indicating an OS-level issue
		return "", fmt.Errorf("failed to read crypto/rand bytes for secret: %w", err)
	}

	// Encode the random bytes into a URL-safe Base64 string.
	// URLEncoding is preferred over StdEncoding to avoid '+' and '/' characters,
	// which can cause issues in URLs or some configuration files.
	secret := base64.URLEncoding.EncodeToString(randomBytes)

	return secret, nil
}

func main() {
	// --- Generate Client ID ---
	clientID, err := GenerateClientID()
	if err != nil {
		log.Fatalf("Error generating Client ID: %v", err)
	}
	fmt.Printf("Generated Client ID: %s\n", clientID)

	// --- Generate Client Secret ---
	// Let's generate a secret based on 32 bytes of randomness
	secretLengthBytes := 32
	clientSecret, err := GenerateClientSecret(secretLengthBytes)
	if err != nil {
		log.Fatalf("Error generating Client Secret: %v", err)
	}
	fmt.Printf("Generated Client Secret (%d random bytes): %s\n", secretLengthBytes, clientSecret)
	fmt.Printf("Length of generated secret string: %d characters\n", len(clientSecret))

	// --- Example: Stronger Secret ---
	strongerSecretLengthBytes := 64
	strongerClientSecret, err := GenerateClientSecret(strongerSecretLengthBytes)
	if err != nil {
		log.Fatalf("Error generating stronger Client Secret: %v", err)
	}
	fmt.Printf("\nGenerated Stronger Client Secret (%d random bytes): %s\n", strongerSecretLengthBytes, strongerClientSecret)
	fmt.Printf("Length of generated stronger secret string: %d characters\n", len(strongerClientSecret))
}
