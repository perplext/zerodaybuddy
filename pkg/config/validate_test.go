package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateDirectory(t *testing.T) {
	tempDir := t.TempDir()
	
	tests := []struct {
		name            string
		dir             string
		fieldName       string
		createIfMissing bool
		setupFunc       func()
		expectError     bool
		errorContains   string
	}{
		{
			name:            "valid existing directory",
			dir:             tempDir,
			fieldName:       "test_dir",
			createIfMissing: false,
			expectError:     false,
		},
		{
			name:            "empty directory allowed",
			dir:             "",
			fieldName:       "test_dir",
			createIfMissing: false,
			expectError:     false,
		},
		{
			name:            "create missing directory",
			dir:             filepath.Join(tempDir, "new_dir"),
			fieldName:       "test_dir",
			createIfMissing: true,
			expectError:     false,
		},
		{
			name:            "missing directory no create",
			dir:             filepath.Join(tempDir, "missing"),
			fieldName:       "test_dir",
			createIfMissing: false,
			expectError:     true,
			errorContains:   "does not exist",
		},
		{
			name:            "path traversal",
			dir:             "../../../etc",
			fieldName:       "test_dir",
			createIfMissing: false,
			expectError:     true,
			errorContains:   "path traversal not allowed",
		},
		{
			name:            "not a directory",
			dir:             filepath.Join(tempDir, "file.txt"),
			fieldName:       "test_dir",
			createIfMissing: false,
			setupFunc: func() {
				os.WriteFile(filepath.Join(tempDir, "file.txt"), []byte("test"), 0644)
			},
			expectError:   true,
			errorContains: "is not a directory",
		},
		{
			name:            "not writable",
			dir:             filepath.Join(tempDir, "readonly"),
			fieldName:       "test_dir",
			createIfMissing: false,
			setupFunc: func() {
				dir := filepath.Join(tempDir, "readonly")
				os.MkdirAll(dir, 0555) // Read-only
			},
			expectError:   true,
			errorContains: "is not writable",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
			}
			
			err := validateDirectory(tt.dir, tt.fieldName, tt.createIfMissing)
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
			
			// Cleanup
			if tt.name == "not writable" {
				os.Chmod(filepath.Join(tempDir, "readonly"), 0755)
			}
		})
	}
}

func TestValidateLogging(t *testing.T) {
	tests := []struct {
		name          string
		logging       LoggingConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "valid logging config",
			logging: LoggingConfig{
				Level:       "info",
				Format:      "text",
				MaxFileSize: 100,
				MaxBackups:  5,
				MaxAge:      30,
			},
			expectError: false,
		},
		{
			name: "valid with uppercase level",
			logging: LoggingConfig{
				Level: "DEBUG",
			},
			expectError: false,
		},
		{
			name: "empty level allowed",
			logging: LoggingConfig{
				Level: "",
			},
			expectError: false,
		},
		{
			name: "invalid level",
			logging: LoggingConfig{
				Level: "invalid",
			},
			expectError:   true,
			errorContains: "invalid log level",
		},
		{
			name: "invalid format",
			logging: LoggingConfig{
				Format: "xml",
			},
			expectError:   true,
			errorContains: "invalid log format",
		},
		{
			name: "negative max file size",
			logging: LoggingConfig{
				MaxFileSize: -1,
			},
			expectError:   true,
			errorContains: "must be non-negative",
		},
		{
			name: "negative max backups",
			logging: LoggingConfig{
				MaxBackups: -1,
			},
			expectError:   true,
			errorContains: "must be non-negative",
		},
		{
			name: "negative max age",
			logging: LoggingConfig{
				MaxAge: -1,
			},
			expectError:   true,
			errorContains: "must be non-negative",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Logging: tt.logging}
			err := cfg.validateLogging()
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidatePlatforms(t *testing.T) {
	tests := []struct {
		name          string
		hackerone     HackerOneConfig
		bugcrowd      BugcrowdConfig
		expectError   bool
		errorContains string
	}{
		{
			name:        "empty config valid",
			expectError: false,
		},
		{
			name: "valid hackerone config",
			hackerone: HackerOneConfig{
				APIKey:   "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
				Username: "testuser",
				APIUrl:   "https://api.hackerone.com",
			},
			expectError: false,
		},
		{
			name: "hackerone missing username",
			hackerone: HackerOneConfig{
				APIKey: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
			},
			expectError:   true,
			errorContains: "username is required",
		},
		{
			name: "hackerone invalid API key",
			hackerone: HackerOneConfig{
				APIKey:   "short",
				Username: "testuser",
			},
			expectError:   true,
			errorContains: "invalid HackerOne API key",
		},
		{
			name: "hackerone invalid API URL",
			hackerone: HackerOneConfig{
				APIKey:   "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0",
				Username: "testuser",
				APIUrl:   "not-a-url",
			},
			expectError:   true,
			errorContains: "invalid HackerOne API URL",
		},
		{
			name: "valid bugcrowd config",
			bugcrowd: BugcrowdConfig{
				Email:       "test@example.com",
				CookieValue: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
				APIUrl:      "https://bugcrowd.com",
			},
			expectError: false,
		},
		{
			name: "bugcrowd missing email",
			bugcrowd: BugcrowdConfig{
				CookieValue: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
			},
			expectError:   true,
			errorContains: "email is required",
		},
		{
			name: "bugcrowd invalid email",
			bugcrowd: BugcrowdConfig{
				Email:       "not-an-email",
				CookieValue: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
			},
			expectError:   true,
			errorContains: "invalid Bugcrowd email",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				HackerOne: tt.hackerone,
				Bugcrowd:  tt.bugcrowd,
			}
			err := cfg.validatePlatforms()
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateWebServer(t *testing.T) {
	tempDir := t.TempDir()
	
	// Create test TLS files
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	os.WriteFile(certFile, []byte("test cert"), 0644)
	os.WriteFile(keyFile, []byte("test key"), 0644)
	
	tests := []struct {
		name          string
		webServer     WebServerConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "valid config",
			webServer: WebServerConfig{
				Host: "localhost",
				Port: 8080,
			},
			expectError: false,
		},
		{
			name: "invalid host",
			webServer: WebServerConfig{
				Host: "invalid host!",
			},
			expectError:   true,
			errorContains: "invalid web server host",
		},
		{
			name: "invalid port",
			webServer: WebServerConfig{
				Port: 70000,
			},
			expectError:   true,
			errorContains: "invalid web server port",
		},
		{
			name: "valid TLS config",
			webServer: WebServerConfig{
				EnableTLS:   true,
				TLSCertFile: certFile,
				TLSKeyFile:  keyFile,
			},
			expectError: false,
		},
		{
			name: "TLS missing cert",
			webServer: WebServerConfig{
				EnableTLS:  true,
				TLSKeyFile: keyFile,
			},
			expectError:   true,
			errorContains: "TLS cert and key files are required",
		},
		{
			name: "TLS cert not found",
			webServer: WebServerConfig{
				EnableTLS:   true,
				TLSCertFile: "/nonexistent/cert.pem",
				TLSKeyFile:  keyFile,
			},
			expectError:   true,
			errorContains: "TLS cert file not found",
		},
		{
			name: "valid proxy config",
			webServer: WebServerConfig{
				ProxyEnabled: true,
				ProxyPort:    8081,
			},
			expectError: false,
		},
		{
			name: "invalid proxy port",
			webServer: WebServerConfig{
				ProxyEnabled: true,
				ProxyPort:    -1,
			},
			expectError:   true,
			errorContains: "invalid proxy port",
		},
		{
			name: "valid allowed origins",
			webServer: WebServerConfig{
				AllowedOrigins: []string{"*", "http://localhost:3000", "https://example.com"},
			},
			expectError: false,
		},
		{
			name: "invalid allowed origin",
			webServer: WebServerConfig{
				AllowedOrigins: []string{"example.com"},
			},
			expectError:   true,
			errorContains: "invalid allowed origin",
		},
		{
			name: "short session secret",
			webServer: WebServerConfig{
				SessionSecret: "tooshort",
			},
			expectError:   true,
			errorContains: "session secret too short",
		},
		{
			name: "short JWT secret",
			webServer: WebServerConfig{
				JWTSecret: "tooshort",
			},
			expectError:   true,
			errorContains: "JWT secret too short",
		},
		{
			name: "valid secrets",
			webServer: WebServerConfig{
				SessionSecret: "this-is-a-very-long-session-secret-key",
				JWTSecret:     "this-is-a-very-long-jwt-secret-key",
			},
			expectError: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{WebServer: tt.webServer}
			err := cfg.validateWebServer()
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateTools(t *testing.T) {
	tempDir := t.TempDir()
	
	// Create test files
	wordlistFile := filepath.Join(tempDir, "wordlist.txt")
	os.WriteFile(wordlistFile, []byte("word1\nword2"), 0644)
	
	execFile := filepath.Join(tempDir, "tool")
	os.WriteFile(execFile, []byte("#!/bin/sh"), 0755)
	
	tests := []struct {
		name          string
		tools         ToolsConfig
		expectError   bool
		errorContains string
	}{
		{
			name: "valid config",
			tools: ToolsConfig{
				MaxThreads:       10,
				DefaultRateLimit: 100,
			},
			expectError: false,
		},
		{
			name: "zero threads",
			tools: ToolsConfig{
				MaxThreads: 0,
			},
			expectError:   true,
			errorContains: "must be positive",
		},
		{
			name: "too many threads",
			tools: ToolsConfig{
				MaxThreads: 1001,
			},
			expectError:   true,
			errorContains: "too high",
		},
		{
			name: "negative rate limit",
			tools: ToolsConfig{
				MaxThreads:       10,
				DefaultRateLimit: -1,
			},
			expectError:   true,
			errorContains: "must be non-negative",
		},
		{
			name: "valid tool paths",
			tools: ToolsConfig{
				MaxThreads:    10,
				SubfinderPath: execFile,
				NucleiPath:    "nuclei", // Default name is OK
			},
			expectError: false,
		},
		{
			name: "tool not found",
			tools: ToolsConfig{
				MaxThreads:    10,
				SubfinderPath: "/nonexistent/tool",
			},
			expectError:   true,
			errorContains: "not found at path",
		},
		{
			name: "path traversal in tool",
			tools: ToolsConfig{
				MaxThreads:    10,
				SubfinderPath: "../../../bin/sh",
			},
			expectError:   true,
			errorContains: "path traversal not allowed",
		},
		{
			name: "valid wordlist",
			tools: ToolsConfig{
				MaxThreads:      10,
				DefaultWordlist: wordlistFile,
			},
			expectError: false,
		},
		{
			name: "wordlist not found",
			tools: ToolsConfig{
				MaxThreads:      10,
				DefaultWordlist: "/nonexistent/wordlist.txt",
			},
			expectError:   true,
			errorContains: "wordlist not found",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Tools: tt.tools}
			err := cfg.validateTools()
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tempDir := t.TempDir()
	
	tests := []struct {
		name          string
		config        *Config
		expectError   bool
		errorContains string
	}{
		{
			name: "valid config",
			config: &Config{
				DataDir: tempDir,
				LogDir:  tempDir,
				Tools: ToolsConfig{
					MaxThreads: 10,
				},
			},
			expectError: false,
		},
		{
			name: "multiple validation errors",
			config: &Config{
				DataDir: "../../../etc",
				Logging: LoggingConfig{
					Level: "invalid",
				},
				Tools: ToolsConfig{
					MaxThreads: 0,
				},
			},
			expectError:   true,
			errorContains: "path traversal", // First error
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}