package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplext/zerodaybuddy/pkg/validation"
)

// Validate validates the configuration values
func (c *Config) Validate() error {
	// Validate directories
	if err := validateDirectory(c.DataDir, "data_dir", true); err != nil {
		return err
	}
	
	if err := validateDirectory(c.LogDir, "log_dir", true); err != nil {
		return err
	}
	
	// Validate logging configuration
	if err := c.validateLogging(); err != nil {
		return err
	}
	
	// Validate platform configurations
	if err := c.validatePlatforms(); err != nil {
		return err
	}
	
	// Validate web server configuration
	if err := c.validateWebServer(); err != nil {
		return err
	}
	
	// Validate tools configuration
	if err := c.validateTools(); err != nil {
		return err
	}
	
	return nil
}

// validateLogging validates logging configuration
func (c *Config) validateLogging() error {
	// Validate log level
	validLevels := []string{"debug", "info", "warn", "error", "fatal"}
	levelValid := false
	for _, valid := range validLevels {
		if strings.ToLower(c.Logging.Level) == valid {
			levelValid = true
			break
		}
	}
	if !levelValid && c.Logging.Level != "" {
		return fmt.Errorf("invalid log level '%s': must be one of %v", c.Logging.Level, validLevels)
	}
	
	// Validate log format
	if c.Logging.Format != "" && c.Logging.Format != "text" && c.Logging.Format != "json" {
		return fmt.Errorf("invalid log format '%s': must be 'text' or 'json'", c.Logging.Format)
	}
	
	// Validate numeric values
	if c.Logging.MaxFileSize < 0 {
		return fmt.Errorf("invalid max_file_size_mb: must be non-negative")
	}
	
	if c.Logging.MaxBackups < 0 {
		return fmt.Errorf("invalid max_backups: must be non-negative")
	}
	
	if c.Logging.MaxAge < 0 {
		return fmt.Errorf("invalid max_age_days: must be non-negative")
	}
	
	return nil
}

// validatePlatforms validates platform configurations
func (c *Config) validatePlatforms() error {
	// Validate HackerOne config if API key is provided
	if c.HackerOne.APIKey != "" {
		if err := validation.APIKey(c.HackerOne.APIKey, "hackerone"); err != nil {
			return fmt.Errorf("invalid HackerOne API key: %w", err)
		}
		
		if c.HackerOne.Username == "" {
			return fmt.Errorf("HackerOne username is required when API key is provided")
		}
		
		if c.HackerOne.APIUrl != "" {
			if err := validation.ConfigURL(c.HackerOne.APIUrl); err != nil {
				return fmt.Errorf("invalid HackerOne API URL: %w", err)
			}
		}
	}
	
	// Validate Bugcrowd config if cookie is provided
	if c.Bugcrowd.CookieValue != "" {
		if err := validation.APIKey(c.Bugcrowd.CookieValue, "bugcrowd"); err != nil {
			return fmt.Errorf("invalid Bugcrowd session cookie: %w", err)
		}
		
		if c.Bugcrowd.Email == "" {
			return fmt.Errorf("Bugcrowd email is required when cookie is provided")
		}
		
		if err := validation.ValidateEmail(c.Bugcrowd.Email); err != nil {
			return fmt.Errorf("invalid Bugcrowd email: %w", err)
		}
		
		if c.Bugcrowd.APIUrl != "" {
			if err := validation.ConfigURL(c.Bugcrowd.APIUrl); err != nil {
				return fmt.Errorf("invalid Bugcrowd API URL: %w", err)
			}
		}
	}
	
	return nil
}

// validateWebServer validates web server configuration
func (c *Config) validateWebServer() error {
	// Validate host
	if c.WebServer.Host != "" {
		if err := validation.Host(c.WebServer.Host); err != nil {
			return fmt.Errorf("invalid web server host: %w", err)
		}
	}
	
	// Validate port
	if c.WebServer.Port != 0 {
		if err := validation.Port(c.WebServer.Port); err != nil {
			return fmt.Errorf("invalid web server port: %w", err)
		}
	}
	
	// Validate proxy port if proxy is enabled
	if c.WebServer.ProxyEnabled && c.WebServer.ProxyPort != 0 {
		if err := validation.Port(c.WebServer.ProxyPort); err != nil {
			return fmt.Errorf("invalid proxy port: %w", err)
		}
	}
	
	// Validate TLS configuration
	if c.WebServer.EnableTLS {
		if c.WebServer.TLSCertFile == "" || c.WebServer.TLSKeyFile == "" {
			return fmt.Errorf("TLS cert and key files are required when TLS is enabled")
		}
		
		// Check if cert and key files exist
		if _, err := os.Stat(c.WebServer.TLSCertFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS cert file not found: %s", c.WebServer.TLSCertFile)
		}
		
		if _, err := os.Stat(c.WebServer.TLSKeyFile); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s", c.WebServer.TLSKeyFile)
		}
	}
	
	// Validate allowed origins
	for _, origin := range c.WebServer.AllowedOrigins {
		if origin != "*" && !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
			return fmt.Errorf("invalid allowed origin '%s': must be '*' or start with http:// or https://", origin)
		}
	}
	
	// Validate secrets
	if c.WebServer.SessionSecret != "" && len(c.WebServer.SessionSecret) < 32 {
		return fmt.Errorf("session secret too short: should be at least 32 characters")
	}
	
	if c.WebServer.JWTSecret != "" && len(c.WebServer.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret too short: should be at least 32 characters")
	}
	
	return nil
}

// validateTools validates tools configuration
func (c *Config) validateTools() error {
	// Validate numeric values
	if c.Tools.MaxThreads <= 0 {
		return fmt.Errorf("invalid max_threads: must be positive")
	}
	
	if c.Tools.MaxThreads > 1000 {
		return fmt.Errorf("max_threads too high: maximum 1000")
	}
	
	if c.Tools.DefaultRateLimit < 0 {
		return fmt.Errorf("invalid default_rate_limit: must be non-negative")
	}
	
	// Validate tool paths (only if specified)
	toolPaths := map[string]string{
		"subfinder": c.Tools.SubfinderPath,
		"amass":     c.Tools.AmassPath,
		"nuclei":    c.Tools.NucleiPath,
		"httpx":     c.Tools.HTTPXPath,
		"naabu":     c.Tools.NaabuPath,
		"katana":    c.Tools.KatanaPath,
		"ffuf":      c.Tools.FFUFPath,
		"wayback":   c.Tools.WaybackPath,
	}
	
	for tool, path := range toolPaths {
		if path != "" && path != tool { // Default is just the tool name
			// Check if it's an absolute path
			if filepath.IsAbs(path) {
				if _, err := os.Stat(path); os.IsNotExist(err) {
					return fmt.Errorf("%s tool not found at path: %s", tool, path)
				}
			}
			// If relative path, just validate it's not trying path traversal
			if strings.Contains(path, "..") {
				return fmt.Errorf("invalid %s path: path traversal not allowed", tool)
			}
		}
	}
	
	// Validate wordlist if specified
	if c.Tools.DefaultWordlist != "" {
		if _, err := os.Stat(c.Tools.DefaultWordlist); os.IsNotExist(err) {
			return fmt.Errorf("default wordlist not found: %s", c.Tools.DefaultWordlist)
		}
	}
	
	return nil
}

// validateDirectory validates a directory path
func validateDirectory(dir string, name string, createIfMissing bool) error {
	if dir == "" {
		return nil // Will use default
	}
	
	// Clean the path
	cleaned := filepath.Clean(dir)
	
	// Check for path traversal
	if strings.Contains(dir, "..") {
		return fmt.Errorf("invalid %s: path traversal not allowed", name)
	}
	
	// Check if directory exists
	info, err := os.Stat(cleaned)
	if os.IsNotExist(err) {
		if createIfMissing {
			// Try to create it
			if err := os.MkdirAll(cleaned, 0755); err != nil {
				return fmt.Errorf("failed to create %s directory: %w", name, err)
			}
		} else {
			return fmt.Errorf("%s directory does not exist: %s", name, cleaned)
		}
	} else if err != nil {
		return fmt.Errorf("failed to check %s directory: %w", name, err)
	} else if !info.IsDir() {
		return fmt.Errorf("%s is not a directory: %s", name, cleaned)
	}
	
	// Check if writable
	testFile := filepath.Join(cleaned, ".write-test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("%s directory is not writable: %s", name, cleaned)
	}
	os.Remove(testFile)
	
	return nil
}