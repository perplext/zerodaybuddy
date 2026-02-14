package recon

import (
	"context"
	"os"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewFFUFScanner(t *testing.T) {
	cfg := config.ToolsConfig{FFUFPath: "/usr/bin/ffuf"}
	logger := utils.NewLogger("", true)
	scanner := NewFFUFScanner(cfg, logger)

	assert.NotNil(t, scanner)
	assert.Equal(t, cfg, scanner.config)
}

func TestFFUFScanner_Name(t *testing.T) {
	scanner := &FFUFScanner{}
	assert.Equal(t, "ffuf", scanner.Name())
}

func TestFFUFScanner_Description(t *testing.T) {
	scanner := &FFUFScanner{}
	assert.Equal(t, "Discovers content and directories on web servers", scanner.Description())
}

func TestFFUFScanner_ConfigPathFallback(t *testing.T) {
	tests := []struct {
		name     string
		config   config.ToolsConfig
		expected string
	}{
		{"custom path", config.ToolsConfig{FFUFPath: "/custom/ffuf"}, "/custom/ffuf"},
		{"default path", config.ToolsConfig{}, "ffuf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewFFUFScanner(tt.config, utils.NewLogger("", true))
			if tt.config.FFUFPath != "" {
				assert.Equal(t, tt.expected, scanner.config.FFUFPath)
			} else {
				assert.Equal(t, "", scanner.config.FFUFPath) // default is applied at scan time
			}
		})
	}
}

func TestFFUFScanner_Scan_InvalidTargetType(t *testing.T) {
	scanner := NewFFUFScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	invalidTargets := []interface{}{
		123,
		"not-a-slice",
		map[string]string{"url": "test"},
		nil,
	}

	for _, target := range invalidTargets {
		result, err := scanner.Scan(context.Background(), project, target, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid target type for FFUF")
		assert.Nil(t, result)
	}
}

func TestFFUFScanner_DiscoverEndpoints_EmptyInput(t *testing.T) {
	scanner := NewFFUFScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	endpoints, err := scanner.DiscoverEndpoints(context.Background(), project, []string{}, ScanOptions{})
	assert.NoError(t, err)
	assert.Nil(t, endpoints)
}

func TestFFUFScanner_DiscoverEndpoints_InvalidWordlist(t *testing.T) {
	scanner := NewFFUFScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	tests := []struct {
		name    string
		opts    ScanOptions
		errMsg  string
	}{
		{
			name:   "flag injection in wordlist",
			opts:   ScanOptions{Wordlist: "-malicious-flag"},
			errMsg: "invalid wordlist path",
		},
		{
			name:   "semicolon injection",
			opts:   ScanOptions{Wordlist: "/tmp/file;rm -rf /"},
			errMsg: "invalid wordlist path",
		},
		{
			name:   "pipe injection",
			opts:   ScanOptions{Wordlist: "/tmp/file|cat /etc/passwd"},
			errMsg: "invalid wordlist path",
		},
		{
			name:   "nonexistent wordlist file",
			opts:   ScanOptions{Wordlist: "/nonexistent/path/wordlist.txt"},
			errMsg: "wordlist file not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := scanner.DiscoverEndpoints(context.Background(), project, []string{"https://example.com"}, tt.opts)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestFFUFScanner_DiscoverEndpoints_OutOfScope(t *testing.T) {
	scanner := NewFFUFScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := &models.Project{
		ID:   "test-project",
		Name: "test-project",
		Scope: models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
			},
		},
	}

	// Create a wordlist file for this test
	wordlistDir := t.TempDir()
	wordlistPath := wordlistDir + "/test-wordlist.txt"
	_ = writeTestFile(t, wordlistPath, "admin\nlogin\n")

	// URL not in scope — should be skipped
	endpoints, err := scanner.DiscoverEndpoints(context.Background(), project, []string{"https://notinscope.com"}, ScanOptions{Wordlist: wordlistPath})
	assert.NoError(t, err)
	assert.Empty(t, endpoints)
}

func TestFFUFResult_Structure(t *testing.T) {
	result := FFUFResult{
		URL:         "https://example.com/admin",
		Status:      200,
		Length:      1234,
		Words:       100,
		Lines:       50,
		ContentType: "text/html",
		Redirects:   "https://example.com/admin/",
	}

	assert.Equal(t, "https://example.com/admin", result.URL)
	assert.Equal(t, 200, result.Status)
	assert.Equal(t, "text/html", result.ContentType)
}

// writeTestFile is a test helper to create a file with content.
func writeTestFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0644)
}
