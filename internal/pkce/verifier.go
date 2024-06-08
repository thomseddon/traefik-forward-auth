package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

type CodeVerifier struct {
	Value string
}

func CreateCodeVerifier() (*CodeVerifier, error) {
	secureRandomString, err := generateSecureRandomString(32)
	if err != nil {
		return nil, err
	}
	return &CodeVerifier{
		Value: secureRandomString,
	}, nil
}

func (v *CodeVerifier) String() string {
	return v.Value
}

func (v *CodeVerifier) CodeChallengeS256() string {
	h := sha256.New()
	h.Write([]byte(v.Value))
	hash := h.Sum(nil)

	return encode(hash)
}

func GenerateNonce() (string, error) {
	return generateSecureRandomString(32)
}

func generateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure random string: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func encode(msg []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(msg)
	return encoded
}
