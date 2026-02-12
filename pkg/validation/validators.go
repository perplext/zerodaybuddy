package validation

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"unicode"
)

var (
	// Additional error types
	ErrInvalidUsername      = errors.New("invalid username")
	ErrInvalidPassword      = errors.New("invalid password")
	ErrInvalidAPIKey        = errors.New("invalid API key")
	ErrInvalidConfigValue   = errors.New("invalid configuration value")
	ErrInvalidInteger       = errors.New("invalid integer value")
	ErrInvalidSeverity      = errors.New("invalid severity")
	ErrInvalidTargetType    = errors.New("invalid target type")
	ErrInvalidMigrationName = errors.New("invalid migration name")

	// Username validation
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)
	
	// API key patterns
	hackeroneAPIKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9]{40,}$`)
	
	// Migration name pattern
	migrationNameRegex = regexp.MustCompile(`^[a-z0-9_]+$`)
)

// ValidSeverities contains the list of valid finding severities
var ValidSeverities = []string{"critical", "high", "medium", "low", "info"}

// ValidTargetTypes contains the list of valid scan target types
var ValidTargetTypes = []string{"all", "host", "endpoint", "url"}

// Username validates a username
func Username(username string) error {
	if username == "" {
		return fmt.Errorf("%w: username cannot be empty", ErrInvalidUsername)
	}
	
	if len(username) < 3 {
		return fmt.Errorf("%w: username must be at least 3 characters", ErrInvalidUsername)
	}
	
	if len(username) > 50 {
		return fmt.Errorf("%w: username too long (max 50 characters)", ErrInvalidUsername)
	}
	
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("%w: username can only contain letters, numbers, dots, hyphens, and underscores", ErrInvalidUsername)
	}
	
	// Prevent some common problematic usernames
	reserved := []string{"admin", "root", "system", "api", "test"}
	lower := strings.ToLower(username)
	for _, r := range reserved {
		if lower == r {
			return fmt.Errorf("%w: username '%s' is reserved", ErrInvalidUsername, username)
		}
	}
	
	return nil
}

// Password validates password strength
func Password(password string) error {
	if password == "" {
		return fmt.Errorf("%w: password cannot be empty", ErrInvalidPassword)
	}
	
	if len(password) < 8 {
		return fmt.Errorf("%w: password must be at least 8 characters", ErrInvalidPassword)
	}
	
	if len(password) > 128 {
		return fmt.Errorf("%w: password too long (max 128 characters)", ErrInvalidPassword)
	}
	
	// Check for character variety
	var (
		hasUpper   bool
		hasLower   bool
		hasDigit   bool
		hasSpecial bool
	)
	
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}
	
	// Require at least 3 out of 4 character types
	complexity := 0
	if hasUpper {
		complexity++
	}
	if hasLower {
		complexity++
	}
	if hasDigit {
		complexity++
	}
	if hasSpecial {
		complexity++
	}
	
	if complexity < 3 {
		return fmt.Errorf("%w: password must contain at least 3 of: uppercase, lowercase, digits, special characters", ErrInvalidPassword)
	}
	
	// Check for common weak passwords
	weakPasswords := []string{
		"password", "12345678", "qwerty", "admin123", "letmein",
		"welcome", "monkey", "dragon", "football", "iloveyou",
	}
	
	lower := strings.ToLower(password)
	for _, weak := range weakPasswords {
		if strings.Contains(lower, weak) {
			return fmt.Errorf("%w: password is too common or weak", ErrInvalidPassword)
		}
	}
	
	return nil
}

// APIKey validates an API key format
func APIKey(key string, platform string) error {
	if key == "" {
		return fmt.Errorf("%w: API key cannot be empty", ErrInvalidAPIKey)
	}
	
	// Remove common prefixes
	key = strings.TrimPrefix(key, "Bearer ")
	key = strings.TrimSpace(key)
	
	switch platform {
	case "hackerone":
		// Allow base64 encoded keys and other formats
		if len(key) < 20 {
			return fmt.Errorf("%w: must be at least 40 characters for HackerOne", ErrInvalidAPIKey)
		}
	case "bugcrowd":
		// Bugcrowd uses session cookies, so just check length
		if len(key) < 20 {
			return fmt.Errorf("%w: Bugcrowd session cookie seems too short", ErrInvalidAPIKey)
		}
	default:
		// Generic API key validation
		if len(key) < 16 {
			return fmt.Errorf("%w: API key seems too short", ErrInvalidAPIKey)
		}
		if len(key) > 512 {
			return fmt.Errorf("%w: API key seems too long", ErrInvalidAPIKey)
		}
	}
	
	return nil
}

// PositiveInteger validates that a value is a positive integer
func PositiveInteger(value int, fieldName string) error {
	if value <= 0 {
		return fmt.Errorf("%w: %s must be positive", ErrInvalidInteger, fieldName)
	}
	return nil
}

// IntegerRange validates that an integer is within a range
func IntegerRange(value int, min int, max int, fieldName string) error {
	if value < min || value > max {
		return fmt.Errorf("%w: %s must be between %d and %d", ErrInvalidInteger, fieldName, min, max)
	}
	return nil
}

// Severity validates a finding severity level
func Severity(severity string) error {
	severity = strings.ToLower(strings.TrimSpace(severity))
	for _, valid := range ValidSeverities {
		if severity == valid {
			return nil
		}
	}
	return fmt.Errorf("%w: must be one of: %s", ErrInvalidSeverity, strings.Join(ValidSeverities, ", "))
}

// TargetType validates a scan target type
func TargetType(targetType string) error {
	targetType = strings.ToLower(strings.TrimSpace(targetType))
	for _, valid := range ValidTargetTypes {
		if targetType == valid {
			return nil
		}
	}
	return fmt.Errorf("%w: must be one of: %s", ErrInvalidTargetType, strings.Join(ValidTargetTypes, ", "))
}

// ConfigURL validates a configuration URL (allows internal URLs)
func ConfigURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("%w: URL cannot be empty", ErrInvalidConfigValue)
	}
	
	// For config URLs, we allow internal hosts
	return ScopeURL(urlStr, true)
}

// IPAddress validates an IP address
func IPAddress(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// MigrationName validates a database migration name
func MigrationName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: migration name cannot be empty", ErrInvalidMigrationName)
	}
	
	if len(name) < 3 {
		return fmt.Errorf("%w: migration name must be at least 3 characters", ErrInvalidMigrationName)
	}
	
	if len(name) > 50 {
		return fmt.Errorf("%w: migration name too long (max 50 characters)", ErrInvalidMigrationName)
	}
	
	if !migrationNameRegex.MatchString(name) {
		return fmt.Errorf("%w: migration name can only contain lowercase letters, numbers, and underscores", ErrInvalidMigrationName)
	}
	
	return nil
}

// SanitizeString removes potentially dangerous characters from a string
func SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")
	
	// Trim whitespace
	input = strings.TrimSpace(input)
	
	// Remove control characters
	var sanitized strings.Builder
	for _, r := range input {
		if r == '\t' || r == '\n' || r == '\r' {
			sanitized.WriteRune(' ')
		} else if !unicode.IsControl(r) {
			sanitized.WriteRune(r)
		}
	}
	
	return sanitized.String()
}

// TruncateString safely truncates a string to a maximum length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	
	// Truncate at rune boundary to avoid breaking UTF-8
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	
	return string(runes[:maxLen])
}