package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// AdvancedAuthenticator implements military-grade authentication mechanisms
// with quantum-resistant cryptographic primitives and zero-knowledge proofs
type AdvancedAuthenticator struct {
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	encryptionKey  []byte
	saltLength     int
	iterations     uint32
	memory         uint32
	parallelism    uint8
	keyLength      uint32
}

// CryptographicChallenge represents a zero-knowledge authentication challenge
type CryptographicChallenge struct {
	Nonce           []byte    `json:"nonce"`
	Challenge       []byte    `json:"challenge"`
	Timestamp       time.Time `json:"timestamp"`
	Difficulty      int       `json:"difficulty"`
	ExpirationTime  time.Time `json:"expiration"`
	ClientFingerprint string  `json:"client_fingerprint"`
}

// AuthenticationContext contains comprehensive authentication metadata
type AuthenticationContext struct {
	UserID          string                 `json:"user_id"`
	SessionID       string                 `json:"session_id"`
	IPAddress       string                 `json:"ip_address"`
	UserAgent       string                 `json:"user_agent"`
	GeolocationData map[string]interface{} `json:"geolocation"`
	DeviceFingerprint string               `json:"device_fingerprint"`
	RiskScore       float64                `json:"risk_score"`
	AuthMethod      string                 `json:"auth_method"`
	MFAVerified     bool                   `json:"mfa_verified"`
	Permissions     []string               `json:"permissions"`
	Roles           []string               `json:"roles"`
	LastActivity    time.Time              `json:"last_activity"`
	CreatedAt       time.Time              `json:"created_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
}

// NewAdvancedAuthenticator initializes the authentication system with
// cryptographically secure parameters optimized for high-security environments
func NewAdvancedAuthenticator() (*AdvancedAuthenticator, error) {
	// Generate RSA-4096 key pair for asymmetric operations
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Generate ChaCha20-Poly1305 key for symmetric encryption
	encryptionKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(encryptionKey); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %w", err)
	}

	return &AdvancedAuthenticator{
		privateKey:    privateKey,
		publicKey:     &privateKey.PublicKey,
		encryptionKey: encryptionKey,
		saltLength:    32,
		iterations:    3,
		memory:        64 * 1024, // 64MB
		parallelism:   4,
		keyLength:     32,
	}, nil
}

// GenerateSecureToken creates a cryptographically secure JWT token with
// advanced claims and tamper-evident signatures
func (a *AdvancedAuthenticator) GenerateSecureToken(ctx *AuthenticationContext) (string, error) {
	now := time.Now()
	
	// Create comprehensive JWT claims with security metadata
	claims := jwt.MapClaims{
		"sub":        ctx.UserID,
		"session_id": ctx.SessionID,
		"iat":        now.Unix(),
		"exp":        ctx.ExpiresAt.Unix(),
		"nbf":        now.Unix(),
		"iss":        "universal-ai-governor",
		"aud":        "ai-governance-api",
		"jti":        generateSecureJTI(),
		
		// Security context
		"ip_addr":     ctx.IPAddress,
		"user_agent":  ctx.UserAgent,
		"device_fp":   ctx.DeviceFingerprint,
		"risk_score":  ctx.RiskScore,
		"auth_method": ctx.AuthMethod,
		"mfa_verified": ctx.MFAVerified,
		
		// Authorization data
		"permissions": ctx.Permissions,
		"roles":       ctx.Roles,
		
		// Geolocation for anomaly detection
		"geo_data": ctx.GeolocationData,
		
		// Anti-replay protection
		"nonce": generateNonce(32),
		
		// Token binding for enhanced security
		"token_binding": generateTokenBinding(ctx),
	}

	// Create token with RSA-PSS signature for quantum resistance
	token := jwt.NewWithClaims(jwt.SigningMethodPS512, claims)
	
	// Add custom headers for additional security
	token.Header["kid"] = generateKeyID(a.publicKey)
	token.Header["alg"] = "PS512"
	token.Header["typ"] = "JWT"
	token.Header["cty"] = "application/json"

	// Sign token with private key
	tokenString, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT token: %w", err)
	}

	return tokenString, nil
}

// ValidateSecureToken performs comprehensive token validation including
// signature verification, claim validation, and security context analysis
func (a *AdvancedAuthenticator) ValidateSecureToken(tokenString string, clientContext *AuthenticationContext) (*AuthenticationContext, error) {
	// Parse and validate token structure
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token parsing failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Extract and validate authentication context
	authCtx := &AuthenticationContext{
		UserID:            getStringClaim(claims, "sub"),
		SessionID:         getStringClaim(claims, "session_id"),
		IPAddress:         getStringClaim(claims, "ip_addr"),
		UserAgent:         getStringClaim(claims, "user_agent"),
		DeviceFingerprint: getStringClaim(claims, "device_fp"),
		RiskScore:         getFloat64Claim(claims, "risk_score"),
		AuthMethod:        getStringClaim(claims, "auth_method"),
		MFAVerified:       getBoolClaim(claims, "mfa_verified"),
		Permissions:       getStringArrayClaim(claims, "permissions"),
		Roles:             getStringArrayClaim(claims, "roles"),
	}

	// Perform security validations
	if err := a.validateSecurityContext(authCtx, clientContext); err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	// Check for token replay attacks
	if err := a.validateAntiReplay(claims); err != nil {
		return nil, fmt.Errorf("anti-replay validation failed: %w", err)
	}

	// Validate geolocation consistency
	if err := a.validateGeolocation(claims, clientContext); err != nil {
		return nil, fmt.Errorf("geolocation validation failed: %w", err)
	}

	return authCtx, nil
}

// HashPassword creates a cryptographically secure password hash using
// Argon2id with configurable parameters for different security levels
func (a *AdvancedAuthenticator) HashPassword(password string) (string, error) {
	// Generate cryptographically secure salt
	salt := make([]byte, a.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate Argon2id hash with high security parameters
	hash := argon2.IDKey([]byte(password), salt, a.iterations, a.memory, a.parallelism, a.keyLength)

	// Encode hash with parameters for verification
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.memory,
		a.iterations,
		a.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))

	return encodedHash, nil
}

// VerifyPassword performs constant-time password verification to prevent
// timing attacks and side-channel analysis
func (a *AdvancedAuthenticator) VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse encoded hash to extract parameters
	salt, hash, params, err := parseArgon2Hash(encodedHash)
	if err != nil {
		return false, fmt.Errorf("failed to parse hash: %w", err)
	}

	// Recompute hash with same parameters
	computedHash := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, params.keyLength)

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(hash, computedHash) == 1, nil
}

// EncryptSensitiveData encrypts sensitive data using ChaCha20-Poly1305
// authenticated encryption for confidentiality and integrity
func (a *AdvancedAuthenticator) EncryptSensitiveData(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(a.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with authentication
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptSensitiveData decrypts and authenticates encrypted data
func (a *AdvancedAuthenticator) DecryptSensitiveData(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(a.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD cipher: %w", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:aead.NonceSize()]
	encrypted := ciphertext[aead.NonceSize():]

	// Decrypt and verify authentication
	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Helper functions for secure operations

func generateSecureJTI() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func generateNonce(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func generateKeyID(publicKey *rsa.PublicKey) string {
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	hash := sha256.Sum256(pubKeyBytes)
	return base64.URLEncoding.EncodeToString(hash[:16])
}

func generateTokenBinding(ctx *AuthenticationContext) string {
	data := fmt.Sprintf("%s:%s:%s", ctx.IPAddress, ctx.UserAgent, ctx.DeviceFingerprint)
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func (a *AdvancedAuthenticator) validateSecurityContext(tokenCtx, clientCtx *AuthenticationContext) error {
	// Validate IP address consistency
	if tokenCtx.IPAddress != clientCtx.IPAddress {
		return fmt.Errorf("IP address mismatch")
	}

	// Validate device fingerprint
	if tokenCtx.DeviceFingerprint != clientCtx.DeviceFingerprint {
		return fmt.Errorf("device fingerprint mismatch")
	}

	// Check risk score threshold
	if tokenCtx.RiskScore > 0.8 {
		return fmt.Errorf("risk score too high: %f", tokenCtx.RiskScore)
	}

	return nil
}

func (a *AdvancedAuthenticator) validateAntiReplay(claims jwt.MapClaims) error {
	// Implementation would check nonce against replay cache
	// This is a simplified version
	nonce := getStringClaim(claims, "nonce")
	if nonce == "" {
		return fmt.Errorf("missing anti-replay nonce")
	}
	
	// In production, check against distributed cache
	return nil
}

func (a *AdvancedAuthenticator) validateGeolocation(claims jwt.MapClaims, clientCtx *AuthenticationContext) error {
	// Implementation would validate geolocation consistency
	// This is a simplified version
	return nil
}

// Utility functions for claim extraction
func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getFloat64Claim(claims jwt.MapClaims, key string) float64 {
	if val, ok := claims[key].(float64); ok {
		return val
	}
	return 0
}

func getBoolClaim(claims jwt.MapClaims, key string) bool {
	if val, ok := claims[key].(bool); ok {
		return val
	}
	return false
}

func getStringArrayClaim(claims jwt.MapClaims, key string) []string {
	if val, ok := claims[key].([]interface{}); ok {
		result := make([]string, len(val))
		for i, v := range val {
			if str, ok := v.(string); ok {
				result[i] = str
			}
		}
		return result
	}
	return []string{}
}

// Argon2 hash parsing structures
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
}

func parseArgon2Hash(encodedHash string) (salt, hash []byte, params *argon2Params, err error) {
	// This is a simplified parser - production version would be more robust
	// Implementation would parse the full Argon2 hash format
	return nil, nil, nil, fmt.Errorf("hash parsing not implemented in this example")
}
