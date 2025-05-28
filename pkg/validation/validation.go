package validation

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	// Error types
	ErrInvalidPlatform     = errors.New("invalid platform: must be 'hackerone' or 'bugcrowd'")
	ErrInvalidConcurrency  = errors.New("invalid concurrency: must be between 1 and 100")
	ErrInvalidPort         = errors.New("invalid port: must be between 1 and 65535")
	ErrPrivilegedPort      = errors.New("privileged port: ports below 1024 require root privileges")
	ErrInvalidHost         = errors.New("invalid host: must be a valid hostname or IP address")
	ErrInvalidUUID         = errors.New("invalid UUID format")
	ErrInvalidReportFormat = errors.New("invalid report format: must be 'markdown' or 'pdf'")
	ErrPathTraversal       = errors.New("path traversal detected")
	ErrInvalidPath         = errors.New("invalid file path")
	ErrInvalidURL          = errors.New("invalid URL format")
	ErrInvalidProjectName  = errors.New("invalid project name: must contain only alphanumeric characters, hyphens, and underscores")
	ErrInvalidHandle       = errors.New("invalid handle: must contain only alphanumeric characters, hyphens, and underscores")
	ErrInvalidEmail        = errors.New("invalid email format")

	// Regular expressions
	projectNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	handleRegex      = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	hostnameRegex    = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	emailRegex       = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// ValidPlatforms contains the list of supported bug bounty platforms
var ValidPlatforms = []string{"hackerone", "bugcrowd"}

// ValidReportFormats contains the list of supported report formats
var ValidReportFormats = []string{"markdown", "pdf"}

// Platform validates a bug bounty platform string
func Platform(platform string) error {
	platform = strings.ToLower(strings.TrimSpace(platform))
	for _, valid := range ValidPlatforms {
		if platform == valid {
			return nil
		}
	}
	return ErrInvalidPlatform
}

// Concurrency validates concurrency limits
func Concurrency(value int) error {
	if value < 1 || value > 100 {
		return ErrInvalidConcurrency
	}
	return nil
}

// Port validates a network port number
func Port(port int) error {
	if port < 1 || port > 65535 {
		return ErrInvalidPort
	}
	// Check if it's a privileged port and user is not root
	if port < 1024 && os.Geteuid() != 0 {
		return ErrPrivilegedPort
	}
	return nil
}

// Host validates a hostname or IP address
func Host(host string) error {
	// Check if it's a valid IP address
	if net.ParseIP(host) != nil {
		return nil
	}
	
	// Check if it's localhost
	if host == "localhost" {
		return nil
	}
	
	// Check if it's a valid hostname
	if !hostnameRegex.MatchString(host) {
		return ErrInvalidHost
	}
	
	return nil
}

// UUID validates a UUID string
func UUID(id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return ErrInvalidUUID
	}
	return nil
}

// ReportFormat validates a report format string
func ReportFormat(format string) error {
	format = strings.ToLower(strings.TrimSpace(format))
	for _, valid := range ValidReportFormats {
		if format == valid {
			return nil
		}
	}
	return ErrInvalidReportFormat
}

// FilePath validates a file path and checks for path traversal attempts
func FilePath(path string) error {
	if path == "" {
		return nil // Empty path is allowed (will use default)
	}
	
	// Clean the path
	cleaned := filepath.Clean(path)
	
	// Check for path traversal
	if strings.Contains(path, "..") {
		return ErrPathTraversal
	}
	
	// Ensure the path is within current directory or absolute
	abs, err := filepath.Abs(cleaned)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPath, err)
	}
	
	// Get current directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}
	
	// Allow paths within current directory or in home directory
	homeDir, _ := os.UserHomeDir()
	if !strings.HasPrefix(abs, cwd) && !strings.HasPrefix(abs, homeDir) {
		// If it's not in current dir or home dir, check if parent directory exists
		dir := filepath.Dir(abs)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return fmt.Errorf("%w: parent directory does not exist", ErrInvalidPath)
		}
	}
	
	return nil
}

// URL validates a URL string
func URL(urlStr string) error {
	if urlStr == "" {
		return ErrInvalidURL
	}
	
	u, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	
	// Check scheme
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme must be http or https", ErrInvalidURL)
	}
	
	// Check host
	if u.Host == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidURL)
	}
	
	// Prevent scanning localhost/internal IPs by default
	if isInternalHost(u.Host) {
		return fmt.Errorf("%w: scanning internal hosts is not allowed", ErrInvalidURL)
	}
	
	return nil
}

// ProjectName validates a project name
func ProjectName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidProjectName)
	}
	
	if len(name) > 100 {
		return fmt.Errorf("%w: name too long (max 100 characters)", ErrInvalidProjectName)
	}
	
	if !projectNameRegex.MatchString(name) {
		return ErrInvalidProjectName
	}
	
	return nil
}

// Handle validates a program handle
func Handle(handle string) error {
	if handle == "" {
		return fmt.Errorf("%w: handle cannot be empty", ErrInvalidHandle)
	}
	
	if len(handle) > 100 {
		return fmt.Errorf("%w: handle too long (max 100 characters)", ErrInvalidHandle)
	}
	
	if !handleRegex.MatchString(handle) {
		return ErrInvalidHandle
	}
	
	return nil
}

// isInternalHost checks if a host is internal/localhost
func isInternalHost(host string) bool {
	// Remove port if present
	hostname, _, _ := net.SplitHostPort(host)
	if hostname == "" {
		hostname = host
	}
	
	// Check common internal hostnames
	internalHosts := []string{"localhost", "127.0.0.1", "::1", "0.0.0.0"}
	for _, internal := range internalHosts {
		if hostname == internal {
			return true
		}
	}
	
	// Check if it's a private IP
	ip := net.ParseIP(hostname)
	if ip != nil {
		return ip.IsLoopback() || ip.IsPrivate()
	}
	
	return false
}

// ValidateEmail validates an email address format
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email cannot be empty", ErrInvalidEmail)
	}
	
	if len(email) > 254 {
		return fmt.Errorf("%w: email too long (max 254 characters)", ErrInvalidEmail)
	}
	
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}
	
	return nil
}

// ValidationError creates a structured validation error
func ValidationError(field, message string) error {
	return fmt.Errorf("validation error for field '%s': %s", field, message)
}

// ScopeURL validates a URL against a scope (used for scan targets)
func ScopeURL(urlStr string, allowInternal bool) error {
	// First validate the URL format
	if err := URL(urlStr); err != nil {
		// If internal hosts are allowed and that's the only error, check again
		if allowInternal && strings.Contains(err.Error(), "internal hosts") {
			u, _ := url.Parse(urlStr)
			if u != nil && u.Scheme != "" && u.Host != "" {
				return nil
			}
		}
		return err
	}
	
	return nil
}