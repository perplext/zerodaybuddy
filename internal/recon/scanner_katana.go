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

// KatanaScanner implements the Scanner interface for Katana web crawler
type KatanaScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewKatanaScanner creates a new Katana scanner
func NewKatanaScanner(config config.ToolsConfig, logger *utils.Logger) Scanner {
	return &KatanaScanner{
		config: config,
		logger: logger,
	}
}

// Name returns the name of the scanner
func (s *KatanaScanner) Name() string {
	return "katana"
}

// Description returns a description of the scanner
func (s *KatanaScanner) Description() string {
	return "Crawls websites to discover endpoints"
}

// KatanaResult represents a parsed result from Katana
type KatanaResult struct {
	Timestamp string `json:"timestamp"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	Body      string `json:"body,omitempty"`
}

// Scan performs web crawling on given URLs
func (s *KatanaScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	urls, ok := target.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Katana: %T", target)
	}

	if len(urls) == 0 {
		return []KatanaResult{}, nil
	}

	s.logger.Debug("Starting Katana scan for %d URLs", len(urls))

	// Ensure we have the path to katana
	katanaPath := s.config.KatanaPath
	if katanaPath == "" {
		katanaPath = "katana"
	}

	// Create a temporary directory for input/output
	tempDir, err := os.MkdirTemp("", "zerodaybuddy-katana")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	allResults := []KatanaResult{}

	// Process each URL separately
	for _, url := range urls {
		// Skip if the URL is not in scope
		if !project.Scope.IsInScope(models.AssetTypeURL, url) {
			s.logger.Debug("Skipping out-of-scope URL: %s", url)
			continue
		}

		s.logger.Debug("Running Katana on URL: %s", url)

		outputFile := filepath.Join(tempDir, fmt.Sprintf("katana_%d.json", len(allResults)))

		// Build command arguments
		args := []string{
			"-u", url,
			"-o", outputFile,
			"-json",
			"-silent",
			"-field", "url,path,status",
			"-known-files", "js,xml,json",
			"-rate-limit", "10", // Rate limiting
			"-timeout", "10",
			"-js-crawl",
			"-automatic-form-fill",
		}

		// Set crawling depth
		depth := 3 // Default depth
		if options != nil {
			if d, ok := options["depth"].(int); ok && d > 0 {
				depth = d
			}
		}
		args = append(args, "-depth", fmt.Sprintf("%d", depth))

		// Execute the command
		cmd := exec.CommandContext(ctx, katanaPath, args...)
		if _, err := cmd.Output(); err != nil {
			// Check if it's an ExitError which might contain stderr
			if exitErr, ok := err.(*exec.ExitError); ok {
				s.logger.Warn("Katana failed for %s: %v, stderr: %s", url, err, exitErr.Stderr)
			} else {
				s.logger.Warn("Katana failed for %s: %v", url, err)
			}
			continue // Skip to next URL
		}

		// Read and parse the output
		outputData, err := os.ReadFile(outputFile)
		if err != nil {
			s.logger.Warn("Failed to read Katana output for %s: %v", url, err)
			continue
		}

		// Katana outputs JSON objects one per line
		for _, line := range strings.Split(string(outputData), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			var result KatanaResult
			if err := json.Unmarshal([]byte(line), &result); err != nil {
				s.logger.Warn("Failed to parse Katana result: %v, line: %s", err, line)
				continue
			}

			// Only include endpoints that are in scope
			if project.Scope.IsInScope(models.AssetTypeURL, result.URL) {
				allResults = append(allResults, result)
			}
		}

		s.logger.Debug("Katana found %d endpoints for URL: %s", len(allResults), url)
	}

	s.logger.Debug("Katana scan completed with %d total findings", len(allResults))

	// Convert KatanaResults to []*models.Endpoint for downstream consumption
	endpoints := make([]*models.Endpoint, 0, len(allResults))
	for _, r := range allResults {
		endpoint := katanaResultToEndpoint(r)
		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

// katanaResultToEndpoint converts a KatanaResult to a models.Endpoint
func katanaResultToEndpoint(r KatanaResult) *models.Endpoint {
	endpoint := &models.Endpoint{
		URL:     r.URL,
		Method:  r.Method,
		Status:  r.Status,
		FoundBy: "katana",
	}

	if endpoint.Method == "" {
		endpoint.Method = "GET"
	}

	return endpoint
}
