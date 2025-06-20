package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CurrentTime returns the current time in UTC
func CurrentTime() time.Time {
	return time.Now().UTC()
}

// TimePtr returns a pointer to a time value
func TimePtr(t time.Time) *time.Time {
	return &t
}

// MarshalJSON marshals an object to JSON
func MarshalJSON(v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// UnmarshalJSON unmarshals JSON to an object
func UnmarshalJSON(data string, v interface{}) error {
	return json.Unmarshal([]byte(data), v)
}

// WriteFile writes data to a file
func WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	return ioutil.WriteFile(path, data, 0644)
}

// ReadFile reads data from a file
func ReadFile(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

// IsValidURL checks if a string is a valid HTTP/HTTPS URL
func IsValidURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// SanitizeFileName removes invalid characters from a file name
func SanitizeFileName(name string) string {
	if name == "" {
		return ""
	}
	
	result := ""
	for _, char := range name {
		switch {
		case char >= 'a' && char <= 'z':
			result += string(char)
		case char >= 'A' && char <= 'Z':
			result += string(char)
		case char >= '0' && char <= '9':
			result += string(char)
		case char == '.' || char == '-':
			result += string(char)
		case char == '_':
			result += string(char)
		default:
			// Replace any other character (including spaces and special chars) with underscore
			result += "_"
		}
	}
	
	return result
}

// GenerateSlug generates a slug from a string
func GenerateSlug(s string) string {
	// Convert to lowercase
	result := strings.ToLower(s)
	
	// Replace spaces with hyphens
	result = strings.ReplaceAll(result, " ", "-")
	
	// Remove special characters
	result = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return -1
	}, result)
	
	// Remove consecutive hyphens
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	
	// Trim hyphens from start and end
	result = strings.Trim(result, "-")
	
	return result
}

// IsInScope checks if a URL's domain is in scope
func IsInScope(urlOrDomain string, inScope []string, outOfScope []string) bool {
	// Extract domain from URL if needed
	domain := ExtractDomain(urlOrDomain)
	if domain == "" {
		domain = urlOrDomain // Fallback to treating as domain directly
	}
	
	// Check if domain is explicitly out of scope
	for _, d := range outOfScope {
		if MatchDomain(d, domain) {
			return false
		}
	}
	
	// Check if domain is explicitly in scope
	for _, d := range inScope {
		if MatchDomain(d, domain) {
			return true
		}
	}
	
	return false
}

// MatchDomain checks if a domain matches a pattern (including wildcards)
func MatchDomain(pattern, domain string) bool {
	// Normalize case for comparison
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)
	
	// Exact match
	if pattern == domain {
		return true
	}
	
	// Wildcard match
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		return strings.HasSuffix(domain, suffix) && strings.Count(domain, ".") >= strings.Count(suffix, ".")+1
	}
	
	return false
}

// IsSubdomain checks if the first domain is a subdomain of the second
func IsSubdomain(subdomain, parent string) bool {
	// Normalize domains (remove trailing dot and convert to lowercase)
	parent = strings.ToLower(strings.TrimSuffix(parent, "."))
	subdomain = strings.ToLower(strings.TrimSuffix(subdomain, "."))
	
	// Check dot count first
	if strings.Count(subdomain, ".") <= strings.Count(parent, ".") {
		return false
	}
	
	// Check if subdomain contains parent domain (for cases like example.com.evil.com)
	return strings.HasSuffix(subdomain, "."+parent) || 
		strings.Contains(subdomain, parent+".")
}

// FormatDuration formats a duration in a human-readable form
func FormatDuration(d time.Duration) string {
	if d == 0 {
		return "0ms"
	}
	
	// Handle negative durations
	if d < 0 {
		if d <= -time.Second {
			return fmt.Sprintf("-%ds", int64(-d/time.Second))
		}
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int64(d/time.Second))
	}
	if d < time.Hour {
		minutes := d / time.Minute
		seconds := (d % time.Minute) / time.Second
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	
	hours := d / time.Hour
	minutes := (d % time.Hour) / time.Minute
	seconds := (d % time.Minute) / time.Second
	if seconds > 0 {
		return fmt.Sprintf("%dh %dm %ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dh %dm 0s", hours, minutes)
	}
	return fmt.Sprintf("%dh 0m 0s", hours)
}

// StringInSlice checks if a string is in a slice
func StringInSlice(s string, slice []string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

// UniqueStrings returns a slice with unique strings
func UniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	unique := []string{}
	
	for _, item := range slice {
		if _, exists := keys[item]; !exists {
			keys[item] = true
			unique = append(unique, item)
		}
	}
	
	return unique
}

// ExtractDomain extracts the domain from a URL
func ExtractDomain(urlString string) string {
	if urlString == "" {
		return ""
	}
	
	u, err := url.Parse(urlString)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return "" // Return empty string for invalid URLs
	}
	
	// Extract hostname without port
	host := u.Hostname()
	if host == "" {
		return ""
	}
	
	return host
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// DirExists checks if a directory exists
func DirExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}
