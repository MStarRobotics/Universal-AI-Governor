package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// CryptoUtils provides cryptographic utility functions
type CryptoUtils struct{}

// GenerateSecureToken generates a cryptographically secure random token
func (cu *CryptoUtils) GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// HashData creates SHA-256 hash of input data
func (cu *CryptoUtils) HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SecureCompare performs constant-time comparison to prevent timing attacks
func (cu *CryptoUtils) SecureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	
	result := 0
	for i := 0; i < len(a); i++ {
		result |= int(a[i]) ^ int(b[i])
	}
	
	return result == 0
}
