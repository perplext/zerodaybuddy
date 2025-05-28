package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// HTTPXScanner implements the Scanner interface for httpx
type HTTPXScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewHTTPXScanner creates a new httpx scanner
func NewHTTPXScanner(config config.ToolsConfig, logger *utils.Logger) Scanner {
	return &HTTPXScanner{
		config: config,
		logger: logger,
	}
}

// Name returns the name of the scanner
func (s *HTTPXScanner) Name() string {
	return "httpx"
}

// Description returns a description of the scanner
func (s *HTTPXScanner) Description() string {
	return "Probes for HTTP/HTTPS services on hosts"
}

// HTTPXResult represents a parsed output from httpx
type HTTPXResult struct {
	URL            string `json:"url"`
	StatusCode     int    `json:"status_code"`
	Title          string `json:"title"`
	ContentLength  int    `json:"content_length"`
	TechnologyList string `json:"technology"`
	WebServer      string `json:"webserver"`
	ResponseTime   string `json:"response_time"`
}

// Scan performs HTTP probing on a list of hosts
func (s *HTTPXScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	domains, ok := target.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for HTTPX: %T", target)
	}

	if len(domains) == 0 {
		return []HTTPXResult{}, nil
	}

	s.logger.Debug("Starting HTTPX scan for %d domains", len(domains))

	// Ensure we have the path to httpx
	httpxPath := s.config.HTTPXPath
	if httpxPath == "" {
		httpxPath = "httpx"
	}

	// Create a temporary file to store the domains
	tempDir, err := os.MkdirTemp("", "zerodaybuddy-httpx")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	domainsFile := filepath.Join(tempDir, "domains.txt")
	outputFile := filepath.Join(tempDir, "httpx_output.json")

	// Write domains to the temporary file
	if err := os.WriteFile(domainsFile, []byte(strings.Join(domains, "\n")), 0644); err != nil {
		return nil, fmt.Errorf("failed to write domains to file: %v", err)
	}

	// Build command arguments
	args := []string{
		"-l", domainsFile,
		"-json",
		"-o", outputFile,
		"-status-code",
		"-title",
		"-content-length",
		"-web-server",
		"-tech-detect",
		"-follow-redirects",
		"-timeout", "10",
	}

	// Add rate limiting
	args = append(args, "-rate-limit", "50")

	// Execute the command
	cmd := exec.CommandContext(ctx, httpxPath, args...)
	if _, err := cmd.Output(); err != nil {
		// Check if it's an ExitError which might contain stderr
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("httpx failed: %v, stderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("httpx failed: %v", err)
	}

	// Read and parse the output
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read httpx output: %v", err)
	}

	// HTTPX outputs JSON objects one per line
	var results []HTTPXResult
	for _, line := range strings.Split(string(outputData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result HTTPXResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			s.logger.Warn("Failed to parse httpx result: %v, line: %s", err, line)
			continue
		}

		// Only include in-scope endpoints
		if project.Scope.IsInScope(models.AssetTypeURL, result.URL) {
			results = append(results, result)
		}
	}

	s.logger.Debug("HTTPX found %d HTTP endpoints from %d domains", len(results), len(domains))

	return results, nil
}
