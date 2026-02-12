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

// NucleiScanner implements the Scanner interface for Nuclei vulnerability scanner
type NucleiScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewNucleiScanner creates a new Nuclei scanner
func NewNucleiScanner(config config.ToolsConfig, logger *utils.Logger) Scanner {
	return &NucleiScanner{
		config: config,
		logger: logger,
	}
}

// Name returns the name of the scanner
func (s *NucleiScanner) Name() string {
	return "nuclei"
}

// Description returns a description of the scanner
func (s *NucleiScanner) Description() string {
	return "Scans for known vulnerabilities using templates"
}

// NucleiResult represents a parsed result from Nuclei
type NucleiResult struct {
	TemplateID     string            `json:"template-id"`
	Info           NucleiResultInfo  `json:"info"`
	Host           string            `json:"host"`
	MatcherName    string            `json:"matcher-name,omitempty"`
	Type           string            `json:"type"`
	Severity       string            `json:"severity"`
	ExtractedData  map[string]string `json:"extracted-data,omitempty"`
	IP             string            `json:"ip,omitempty"`
	Timestamp      string            `json:"timestamp"`
	CurlCommand    string            `json:"curl-command,omitempty"`
	MatcherStatus  bool              `json:"matcher-status"`
	MatchedAt      string            `json:"matched-at,omitempty"`
}

// NucleiResultInfo contains information about the template
type NucleiResultInfo struct {
	Name           string   `json:"name"`
	Authors        []string `json:"authors"`
	Tags           []string `json:"tags"`
	Description    string   `json:"description"`
	Reference      []string `json:"reference,omitempty"`
	Severity       string   `json:"severity"`
	Classification struct {
		CVEIDs []string `json:"cve-id,omitempty"`
		CVSSScore  string   `json:"cvss-score,omitempty"`
		CVE     string   `json:"cve,omitempty"`
	} `json:"classification,omitempty"`
}

// Scan performs vulnerability scanning on web endpoints
func (s *NucleiScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	urls, ok := target.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Nuclei: %T", target)
	}

	if len(urls) == 0 {
		return []NucleiResult{}, nil
	}

	s.logger.Debug("Starting Nuclei scan for %d URLs", len(urls))

	// Ensure we have the path to nuclei
	nucleiPath := s.config.NucleiPath
	if nucleiPath == "" {
		nucleiPath = "nuclei"
	}

	// Create a temporary directory for input/output
	tempDir, err := os.MkdirTemp("", "zerodaybuddy-nuclei")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Filter URLs to ensure they're in scope
	var inScopeURLs []string
	for _, url := range urls {
		if project.Scope.IsInScope(models.AssetTypeURL, url) {
			inScopeURLs = append(inScopeURLs, url)
		}
	}

	if len(inScopeURLs) == 0 {
		s.logger.Debug("No in-scope URLs for Nuclei scan")
		return []NucleiResult{}, nil
	}

	// Write targets to the temporary file
	targetsFile := filepath.Join(tempDir, "targets.txt")
	outputFile := filepath.Join(tempDir, "nuclei_output.json")

	if err := os.WriteFile(targetsFile, []byte(strings.Join(inScopeURLs, "\n")), 0644); err != nil {
		return nil, fmt.Errorf("failed to write targets to file: %v", err)
	}

	// Determine which templates to use based on options (whitelist-validated)
	templateFlags := []string{"-t", "technologies,exposures,misconfigurations,cves"}
	if options != nil {
		if templates, ok := options["templates"].(string); ok && templates != "" {
			if validated, err := validateNucleiTemplates(templates); err != nil {
				return nil, fmt.Errorf("invalid templates option: %w", err)
			} else {
				templateFlags = []string{"-t", validated}
			}
		}
	}

	// Build command arguments
	args := []string{
		"-l", targetsFile,
		"-json",
		"-o", outputFile,
		"-silent",
		"-stats",
		"-rate-limit", "10", // Rate limiting
		"-timeout", "5", // 5 second timeout
	}
	args = append(args, templateFlags...)

	// Set severity level (default to medium and above, whitelist-validated)
	severityLevel := "medium,high,critical"
	if options != nil {
		if sev, ok := options["severity"].(string); ok && sev != "" {
			if validated, err := validateNucleiSeverity(sev); err != nil {
				return nil, fmt.Errorf("invalid severity option: %w", err)
			} else {
				severityLevel = validated
			}
		}
	}
	args = append(args, "-severity", severityLevel)

	// Execute the command
	s.logger.Debug("Running Nuclei with args: %v", args)
	cmd := exec.CommandContext(ctx, nucleiPath, args...)
	if _, err := cmd.Output(); err != nil {
		// Nuclei may return non-zero exit code even when it finds issues
		// Check if the output file exists and has content
		if _, statErr := os.Stat(outputFile); statErr != nil {
			// Check if it's an ExitError which might contain stderr
			if exitErr, ok := err.(*exec.ExitError); ok {
				return nil, fmt.Errorf("nuclei failed: %v, stderr: %s", err, exitErr.Stderr)
			}
			return nil, fmt.Errorf("nuclei failed: %v", err)
		}
	}

	// Read and parse the output
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			// No findings
			return []NucleiResult{}, nil
		}
		return nil, fmt.Errorf("failed to read nuclei output: %v", err)
	}

	// Nuclei outputs JSON objects one per line
	var results []NucleiResult
	for _, line := range strings.Split(string(outputData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			s.logger.Warn("Failed to parse nuclei result: %v, line: %s", err, line)
			continue
		}

		results = append(results, result)
	}

	s.logger.Debug("Nuclei found %d vulnerabilities across %d URLs", len(results), len(inScopeURLs))

	return results, nil
}

// allowedNucleiTemplates is the set of valid nuclei template categories.
var allowedNucleiTemplates = map[string]bool{
	"technologies": true, "exposures": true, "misconfigurations": true,
	"cves": true, "vulnerabilities": true, "default-logins": true,
	"network": true, "dns": true, "file": true, "headless": true,
	"helpers": true, "iot": true, "ssl": true, "takeovers": true,
	"token-spray": true, "fuzzing": true, "dast": true,
}

// allowedNucleiSeverities is the set of valid nuclei severity levels.
var allowedNucleiSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// validateNucleiTemplates validates a comma-separated list of template categories.
func validateNucleiTemplates(templates string) (string, error) {
	var valid []string
	for _, t := range strings.Split(templates, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if !allowedNucleiTemplates[t] {
			return "", fmt.Errorf("unknown template category %q", t)
		}
		valid = append(valid, t)
	}
	if len(valid) == 0 {
		return "", fmt.Errorf("no valid template categories specified")
	}
	return strings.Join(valid, ","), nil
}

// validateNucleiSeverity validates a comma-separated list of severity levels.
func validateNucleiSeverity(severity string) (string, error) {
	var valid []string
	for _, s := range strings.Split(severity, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			continue
		}
		if !allowedNucleiSeverities[s] {
			return "", fmt.Errorf("unknown severity level %q", s)
		}
		valid = append(valid, s)
	}
	if len(valid) == 0 {
		return "", fmt.Errorf("no valid severity levels specified")
	}
	return strings.Join(valid, ","), nil
}
