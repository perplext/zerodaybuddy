package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Password hashing parameters
	saltLength  = 16
	keyLength   = 32
	timeParam   = 1
	memory      = 64 * 1024 // 64 MB
	threads     = 4
)

// PasswordHash represents a hashed password with salt and parameters
type PasswordHash struct {
	Salt    []byte
	Hash    []byte
	Time    uint32
	Memory  uint32
	Threads uint8
}

// HashPassword hashes a password using Argon2id
func HashPassword(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate hash
	hash := argon2.IDKey([]byte(password), salt, timeParam, memory, threads, keyLength)

	// Encode to string format: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, timeParam, threads, b64Salt, b64Hash), nil
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, hash string) (bool, error) {
	// Parse the hash
	ph, err := parseHash(hash)
	if err != nil {
		return false, err
	}

	// Generate hash with same parameters
	otherHash := argon2.IDKey([]byte(password), ph.Salt, ph.Time, ph.Memory, ph.Threads, keyLength)

	// Use constant time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(ph.Hash, otherHash) == 1, nil
}

// parseHash parses an Argon2 hash string
func parseHash(hash string) (*PasswordHash, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, fmt.Errorf("invalid version: %w", err)
	}

	if version != argon2.Version {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	var m, t, p uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %w", err)
	}

	hashBytes, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid hash: %w", err)
	}

	return &PasswordHash{
		Salt:    salt,
		Hash:    hashBytes,
		Time:    t,
		Memory:  m,
		Threads: uint8(p),
	}, nil
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	if len(password) > 128 {
		return fmt.Errorf("password must be no more than 128 characters long")
	}

	// Check for at least one uppercase letter
	if matched, _ := regexp.MatchString(`[A-Z]`, password); !matched {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}

	// Check for at least one lowercase letter
	if matched, _ := regexp.MatchString(`[a-z]`, password); !matched {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}

	// Check for at least one digit
	if matched, _ := regexp.MatchString(`\d`, password); !matched {
		return fmt.Errorf("password must contain at least one digit")
	}

	// Check for at least one special character
	if matched, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`, password); !matched {
		return fmt.Errorf("password must contain at least one special character")
	}

	// Check for common weak passwords
	weakPasswords := []string{
		"password", "12345678", "qwerty", "abc123", "password123",
		"admin", "letmein", "welcome", "monkey", "1234567890",
	}

	lowerPassword := strings.ToLower(password)
	for _, weak := range weakPasswords {
		if strings.Contains(lowerPassword, weak) {
			return fmt.Errorf("password contains common weak patterns")
		}
	}

	return nil
}