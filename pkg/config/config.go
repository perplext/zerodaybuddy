package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// Config holds the application configuration
type Config struct {
	// General configuration
	DataDir  string     `mapstructure:"data_dir"`
	LogDir   string     `mapstructure:"log_dir"`
	Debug    bool       `mapstructure:"debug"`
	Logging  LoggingConfig `mapstructure:"logging"`

	// Platform API configuration
	HackerOne HackerOneConfig `mapstructure:"hackerone"`
	Bugcrowd  BugcrowdConfig  `mapstructure:"bugcrowd"`
	Immunefi  ImmunefiConfig  `mapstructure:"immunefi"`

	// Web server configuration
	WebServer WebServerConfig `mapstructure:"web_server"`

	// Tool configuration
	Tools ToolsConfig `mapstructure:"tools"`
}

// HackerOneConfig holds HackerOne platform configuration
type HackerOneConfig struct {
	APIKey    string `mapstructure:"api_key"`
	Username  string `mapstructure:"username"`
	APIUrl    string `mapstructure:"api_url"`
	AuthToken string `mapstructure:"auth_token"`
}

// BugcrowdConfig holds Bugcrowd platform configuration
type BugcrowdConfig struct {
	Email       string `mapstructure:"email"`
	CookieValue string `mapstructure:"cookie_value"`
	APIUrl      string `mapstructure:"api_url"`
}

// ImmunefiConfig holds Immunefi platform configuration
type ImmunefiConfig struct {
	APIUrl string `mapstructure:"api_url"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level          string `mapstructure:"level"`
	Format         string `mapstructure:"format"`
	EnableColors   bool   `mapstructure:"enable_colors"`
	EnableFile     bool   `mapstructure:"enable_file"`
	MaxFileSize    int    `mapstructure:"max_file_size_mb"`
	MaxBackups     int    `mapstructure:"max_backups"`
	MaxAge         int    `mapstructure:"max_age_days"`
	Compress       bool   `mapstructure:"compress"`
}

// WebServerConfig holds web server configuration
type WebServerConfig struct {
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	SessionSecret   string `mapstructure:"session_secret"`
	JWTSecret       string `mapstructure:"jwt_secret"`
	JWTIssuer       string `mapstructure:"jwt_issuer"`
	EnableTLS       bool   `mapstructure:"enable_tls"`
	TLSCertFile     string `mapstructure:"tls_cert_file"`
	TLSKeyFile      string `mapstructure:"tls_key_file"`
	AllowedOrigins  []string `mapstructure:"allowed_origins"`
	ProxyEnabled    bool   `mapstructure:"proxy_enabled"`
	ProxyPort       int    `mapstructure:"proxy_port"`
}

// ToolsConfig holds configuration for external tools
type ToolsConfig struct {
	SubfinderPath    string `mapstructure:"subfinder_path"`
	AmassPath       string `mapstructure:"amass_path"`
	NucleiPath      string `mapstructure:"nuclei_path"`
	DalfoxPath      string `mapstructure:"dalfox_path"`
	HTTPXPath       string `mapstructure:"httpx_path"` // Capitalized for consistency
	NaabuPath       string `mapstructure:"naabu_path"`
	KatanaPath      string `mapstructure:"katana_path"`
	FFUFPath        string `mapstructure:"ffuf_path"`
	WaybackPath     string `mapstructure:"wayback_path"`
	TrivyPath       string `mapstructure:"trivy_path"`
	GitleaksPath    string `mapstructure:"gitleaks_path"`
	MaxThreads      int    `mapstructure:"max_threads"`
	DefaultRateLimit int    `mapstructure:"default_rate_limit"` // Requests per minute
	DefaultWordlist string `mapstructure:"default_wordlist"`
}

// Load loads the configuration from file and environment
func Load() (*Config, error) {
	// Set default configuration file path
	configDir, err := getConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get config directory: %w", err)
	}

	configFile := filepath.Join(configDir, "config.yaml")
	
	// Create default configuration if it doesn't exist
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		if err := createDefaultConfig(configFile); err != nil {
			return nil, fmt.Errorf("failed to create default config: %w", err)
		}
	}

	// Initialize viper
	v := viper.New()
	v.SetConfigFile(configFile)
	
	// Read the configuration file
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Set environment variable prefix
	v.SetEnvPrefix("BUGBASE")
	v.AutomaticEnv()

	// Unmarshal the configuration
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Set defaults if not set
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Join(configDir, "data")
	}
	if cfg.LogDir == "" {
		cfg.LogDir = filepath.Join(configDir, "logs")
	}
	
	// Set logging defaults
	if cfg.Logging.Level == "" {
		if cfg.Debug {
			cfg.Logging.Level = "debug"
		} else {
			cfg.Logging.Level = "info"
		}
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "text"
	}
	if cfg.Logging.MaxFileSize == 0 {
		cfg.Logging.MaxFileSize = 100
	}
	if cfg.Logging.MaxBackups == 0 {
		cfg.Logging.MaxBackups = 5
	}
	if cfg.Logging.MaxAge == 0 {
		cfg.Logging.MaxAge = 30
	}
	
	// Set tool defaults
	if cfg.Tools.MaxThreads == 0 {
		cfg.Tools.MaxThreads = 10
	}
	if cfg.Tools.DefaultRateLimit == 0 {
		cfg.Tools.DefaultRateLimit = 100
	}

	// Ensure directories exist
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	if err := os.MkdirAll(cfg.LogDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// getConfigDir returns the configuration directory path
func getConfigDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user home directory: %w", err)
	}
	
	configDir := filepath.Join(homeDir, ".zerodaybuddy")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create config directory: %w", err)
	}
	
	return configDir, nil
}

// createDefaultConfig creates a default configuration file
func createDefaultConfig(configFile string) error {
	// Default configuration
	defaultConfig := `# ZeroDayBuddy Configuration

# General configuration
data_dir: ""
log_dir: ""
debug: false

# Logging configuration
logging:
  level: "info"
  format: "text"
  enable_colors: true
  enable_file: true
  max_file_size_mb: 100
  max_backups: 5
  max_age_days: 30
  compress: true

# HackerOne configuration
hackerone:
  api_key: ""
  username: ""
  api_url: "https://api.hackerone.com/v1"
  auth_token: ""

# Bugcrowd configuration
bugcrowd:
  email: ""
  cookie_value: ""
  api_url: "https://bugcrowd.com"

# Web server configuration
web_server:
  host: "localhost"
  port: 8080
  session_secret: ""
  jwt_secret: ""
  jwt_issuer: "zerodaybuddy"
  enable_tls: false
  tls_cert_file: ""
  tls_key_file: ""
  allowed_origins: []
  proxy_enabled: false
  proxy_port: 8081

# Tools configuration
tools:
  subfinder_path: "subfinder"
  nuclei_path: "nuclei"
  dalfox_path: "dalfox"
  httpx_path: "httpx"
  naabu_path: "naabu"
  katana_path: "katana"
  ffuf_path: "ffuf"
  max_threads: 10
  default_rate_limit: 100
`

	// Create the directory with restricted permissions (config contains API keys)
	if err := os.MkdirAll(filepath.Dir(configFile), 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write the default configuration with restricted permissions
	if err := os.WriteFile(configFile, []byte(defaultConfig), 0600); err != nil {
		return fmt.Errorf("failed to write default config: %w", err)
	}

	return nil
}

// Save saves the configuration to file
func (c *Config) Save() error {
	configDir, err := getConfigDir()
	if err != nil {
		return fmt.Errorf("failed to get config directory: %w", err)
	}

	configFile := filepath.Join(configDir, "config.yaml")
	
	// Initialize viper
	v := viper.New()
	v.SetConfigFile(configFile)
	
	// Set the configuration values
	v.Set("data_dir", c.DataDir)
	v.Set("log_dir", c.LogDir)
	v.Set("debug", c.Debug)
	v.Set("logging", c.Logging)
	v.Set("hackerone", c.HackerOne)
	v.Set("bugcrowd", c.Bugcrowd)
	v.Set("web_server", c.WebServer)
	v.Set("tools", c.Tools)
	
	// Write the configuration file
	if err := v.WriteConfig(); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	
	return nil
}
