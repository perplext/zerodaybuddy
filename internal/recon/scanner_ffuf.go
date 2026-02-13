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

// FFUFScanner implements the Scanner interface for FFUF content discovery
type FFUFScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewFFUFScanner creates a new FFUF scanner
func NewFFUFScanner(config config.ToolsConfig, logger *utils.Logger) *FFUFScanner {
	return &FFUFScanner{
		config: config,
		logger: logger,
	}
}

// Name returns the name of the scanner
func (s *FFUFScanner) Name() string {
	return "ffuf"
}

// Description returns a description of the scanner
func (s *FFUFScanner) Description() string {
	return "Discovers content and directories on web servers"
}

// FFUFResult represents a parsed result from FFUF
type FFUFResult struct {
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Length     int    `json:"length"`
	Words      int    `json:"words"`
	Lines      int    `json:"lines"`
	ContentType string `json:"content_type"`
	Redirects  string `json:"redirects,omitempty"`
}

// DiscoverEndpoints implements EndpointDiscoverer.
func (s *FFUFScanner) DiscoverEndpoints(ctx context.Context, project *models.Project, urls []string, opts ScanOptions) ([]*models.Endpoint, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	s.logger.Debug("Starting FFUF scan for %d URLs", len(urls))

	// Ensure we have the path to ffuf
	ffufPath := s.config.FFUFPath
	if ffufPath == "" {
		ffufPath = "ffuf"
	}

	// Get wordlist path from options or use default (validate as real file path)
	wordlist := opts.Wordlist
	if wordlist == "" {
		if w, ok := opts.Extra["wordlist"].(string); ok && w != "" {
			wordlist = w
		}
	}
	if wordlist != "" {
		// Reject values that look like flag injection
		if strings.HasPrefix(wordlist, "-") || strings.ContainsAny(wordlist, ";|&`$") {
			return nil, fmt.Errorf("invalid wordlist path: %q", wordlist)
		}
		if _, err := os.Stat(wordlist); err != nil {
			return nil, fmt.Errorf("wordlist file not found: %s", wordlist)
		}
	}

	// If wordlist is still empty, use a default wordlist
	if wordlist == "" {
		if s.config.DefaultWordlist != "" {
			wordlist = s.config.DefaultWordlist
		} else {
			// Use a common wordlist location as fallback
			wordlist = "/usr/share/wordlists/dirb/common.txt"
			// Check if the wordlist exists
			if _, err := os.Stat(wordlist); os.IsNotExist(err) {
				return nil, fmt.Errorf("no default wordlist found, please specify one")
			}
		}
	}

	// Create a temporary directory for output
	tempDir, err := os.MkdirTemp("", "zerodaybuddy-ffuf")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	var allResults []FFUFResult

	// Process each URL separately
	for _, baseURL := range urls {
		// Skip if the URL is not in scope
		if !project.Scope.IsInScope(models.AssetTypeURL, baseURL) {
			s.logger.Debug("Skipping out-of-scope URL: %s", baseURL)
			continue
		}

		s.logger.Debug("Running FFUF on URL: %s", baseURL)

		outputFile := filepath.Join(tempDir, fmt.Sprintf("ffuf_%d.json", len(allResults)))

		// Build command arguments
		args := []string{
			"-u", baseURL + "/FUZZ",
			"-w", wordlist,
			"-mc", "200,201,202,203,204,301,302,307,308,401,403,405",
			"-o", outputFile,
			"-of", "json",
			"-v",
			"-c", // Colorize output
			"-r", // Follow redirects
		}

		// Add rate limiting options
		args = append(args, "-rate", "10")
		args = append(args, "-timeout", "5")

		// Execute the command
		cmd := exec.CommandContext(ctx, ffufPath, args...)
		if _, err := cmd.Output(); err != nil {
			// Since FFUF returns non-zero exit code even on success sometimes,
			// we'll check if the output file exists and has content
			if _, statErr := os.Stat(outputFile); statErr != nil {
				// Check if it's an ExitError which might contain stderr
				if exitErr, ok := err.(*exec.ExitError); ok {
					s.logger.Warn("FFUF failed for %s: %v, stderr: %s", baseURL, err, exitErr.Stderr)
				} else {
					s.logger.Warn("FFUF failed for %s: %v", baseURL, err)
				}
				continue // Skip to next URL
			}
		}

		// Read and parse the output
		outputData, err := os.ReadFile(outputFile)
		if err != nil {
			s.logger.Warn("Failed to read FFUF output for %s: %v", baseURL, err)
			continue
		}

		var ffufOutput struct {
			Results []struct {
				Input       map[string]string `json:"input"`
				Position    int               `json:"position"`
				Status      int               `json:"status"`
				Length      int               `json:"length"`
				Words       int               `json:"words"`
				Lines       int               `json:"lines"`
				ContentType string            `json:"content_type"`
				Redirects   []string          `json:"redirects,omitempty"`
				URL         string            `json:"url"`
			} `json:"results"`
		}

		if err := json.Unmarshal(outputData, &ffufOutput); err != nil {
			s.logger.Warn("Failed to parse FFUF result for %s: %v", baseURL, err)
			continue
		}

		// Convert FFUF results to our format
		for _, result := range ffufOutput.Results {
			ffufResult := FFUFResult{
				URL:         result.URL,
				Status:      result.Status,
				Length:      result.Length,
				Words:       result.Words,
				Lines:       result.Lines,
				ContentType: result.ContentType,
			}

			// Join redirects if any
			if len(result.Redirects) > 0 {
				ffufResult.Redirects = strings.Join(result.Redirects, ",")
			}

			allResults = append(allResults, ffufResult)
		}

		s.logger.Debug("FFUF found %d endpoints for URL: %s", len(ffufOutput.Results), baseURL)
	}

	s.logger.Debug("FFUF scan completed with %d total findings", len(allResults))

	// Convert FFUFResults to []*models.Endpoint for downstream consumption
	endpoints := make([]*models.Endpoint, 0, len(allResults))
	for _, r := range allResults {
		endpoint := &models.Endpoint{
			URL:         r.URL,
			Method:      "GET",
			Status:      r.Status,
			ContentType: r.ContentType,
			FoundBy:     "ffuf",
		}
		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

// Scan implements the legacy Scanner interface.
func (s *FFUFScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	urls, ok := target.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for FFUF: %T", target)
	}
	return s.DiscoverEndpoints(ctx, project, urls, ScanOptions{Extra: options})
}
