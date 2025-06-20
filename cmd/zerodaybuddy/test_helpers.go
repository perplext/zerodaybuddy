package main

import (
	"os"
	"testing"
	
	"github.com/perplext/zerodaybuddy/internal/core"
	"github.com/perplext/zerodaybuddy/pkg/config"
)

// createTestApp creates an App instance for testing
func createTestApp(t *testing.T) (*core.App, func()) {
	// Create a temporary directory for test data
	tmpDir, err := os.MkdirTemp("", "zerodaybuddy-test-*")
	if err != nil {
		t.Fatal(err)
	}

	// Create test config
	cfg := &config.Config{
		DataDir: tmpDir,
		LogDir:  tmpDir,
		Debug:   false,
		Logging: config.LoggingConfig{
			Level:        "info",
			Format:       "text",
			EnableColors: false,
			EnableFile:   false,
		},
		HackerOne: config.HackerOneConfig{
			APIKey:    "test-key",
			Username:  "test-user",
			AuthToken: "test-token",
			APIUrl:   "https://api.hackerone.com/v1",
		},
		Bugcrowd: config.BugcrowdConfig{
			CookieValue: "test-cookie",
			APIUrl:      "https://bugcrowd.com",
		},
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}

	// Create app
	app := core.NewApp(cfg)

	// Return cleanup function
	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return app, cleanup
}

// createTestConfig creates a minimal test configuration
func createTestConfig(dataDir string) *config.Config {
	return &config.Config{
		DataDir: dataDir,
		LogDir:  dataDir,
		Debug:   false,
		Logging: config.LoggingConfig{
			Level:        "info",
			Format:       "text",
			EnableColors: false,
			EnableFile:   false,
		},
		Tools: config.ToolsConfig{
			MaxThreads:       10,
			DefaultRateLimit: 10,
		},
	}
}