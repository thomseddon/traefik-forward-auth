package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// CodeVerifier represents a PKCE code verifier as defined in RFC 7636
type CodeVerifier struct {
	Value string
}

const (
	// MinVerifierLength is the minimum allowed length for a code verifier
	MinVerifierLength = 32
	// MaxVerifierLength is the maximum allowed length for a code verifier
	MaxVerifierLength = 96
	// DefaultVerifierLength is the default length for generated code verifiers
	DefaultVerifierLength = 64
)

// CreateCodeVerifier generates a new code verifier with default length
func CreateCodeVerifier() (*CodeVerifier, error) {
	return CreateCodeVerifierWithLength(DefaultVerifierLength)
}

// CreateCodeVerifierWithLength generates a new code verifier with specified length
func CreateCodeVerifierWithLength(length int) (*CodeVerifier, error) {
	if length < MinVerifierLength || length > MaxVerifierLength {
		return nil, fmt.Errorf("code verifier length must be between %d and %d", MinVerifierLength, MaxVerifierLength)
	}

	secureRandomString, err := generateSecureRandomString(length)
	if err != nil {
		return nil, fmt.Errorf("failed to create code verifier: %w", err)
	}
	return &CodeVerifier{Value: secureRandomString}, nil
}

// CreateCodeVerifierWithCode creates a code verifier from an existing code
func CreateCodeVerifierWithCode(code string) (*CodeVerifier, error) {
	if len(code) < MinVerifierLength || len(code) > MaxVerifierLength {
		return nil, fmt.Errorf("code verifier length must be between %d and %d", MinVerifierLength, MaxVerifierLength)
	}
	return &CodeVerifier{Value: code}, nil
}

// String returns the string representation of the code verifier
func (v *CodeVerifier) String() string {
	return v.Value
}

// CodeChallengeS256 generates the S256 PKCE code challenge as defined in RFC 7636
func (v *CodeVerifier) CodeChallengeS256() string {
	h := sha256.New()
	h.Write([]byte(v.Value))
	return encode(h.Sum(nil))
}

// GenerateNonce generates a cryptographically secure nonce
func GenerateNonce() (string, error) {
	return generateSecureRandomString(DefaultVerifierLength)
}

func generateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func encode(msg []byte) string {
	return base64.RawURLEncoding.EncodeToString(msg)
}
