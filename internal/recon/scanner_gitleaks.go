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

// GitleaksScanner implements VulnerabilityScanner for secrets detection using Gitleaks.
type GitleaksScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewGitleaksScanner creates a new Gitleaks scanner.
func NewGitleaksScanner(config config.ToolsConfig, logger *utils.Logger) *GitleaksScanner {
	return &GitleaksScanner{
		config: config,
		logger: logger,
	}
}

func (s *GitleaksScanner) Name() string        { return "gitleaks" }
func (s *GitleaksScanner) Description() string  { return "Detects secrets and credentials in code and repositories" }

// GitleaksResult represents a single finding from Gitleaks.
type GitleaksResult struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`
	Match       string `json:"Match"`
	Secret      string `json:"Secret"`
	File        string `json:"File"`
	Commit      string `json:"Commit"`
	Entropy     float64 `json:"Entropy"`
	Author      string `json:"Author"`
	Email       string `json:"Email"`
	Date        string `json:"Date"`
	Message     string `json:"Message"`
	Tags        []string `json:"Tags"`
	RuleID      string `json:"RuleID"`
	Fingerprint string `json:"Fingerprint"`
}

// ScanVulnerabilities scans targets for leaked secrets.
// Targets should be file paths or Git repository paths.
func (s *GitleaksScanner) ScanVulnerabilities(ctx context.Context, project *models.Project, targets []string, opts ScanOptions) ([]*models.Finding, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	s.logger.Debug("Starting Gitleaks scan for %d targets", len(targets))

	gitleaksPath := s.config.GitleaksPath
	if gitleaksPath == "" {
		gitleaksPath = "gitleaks"
	}

	tempDir, err := os.MkdirTemp("", "zerodaybuddy-gitleaks")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	var allFindings []*models.Finding

	for i, target := range targets {
		outputFile := filepath.Join(tempDir, fmt.Sprintf("gitleaks_output_%d.json", i))

		args := []string{
			"detect",
			"--source", target,
			"--report-format", "json",
			"--report-path", outputFile,
			"--no-banner",
		}

		s.logger.Debug("Running Gitleaks: %s %v", gitleaksPath, args)
		cmd := exec.CommandContext(ctx, gitleaksPath, args...)
		if _, err := cmd.Output(); err != nil {
			// Gitleaks returns exit code 1 when leaks are found
			if exitErr, ok := err.(*exec.ExitError); ok {
				if exitErr.ExitCode() != 1 {
					s.logger.Warn("Gitleaks failed for %s: %s", target, exitErr.Stderr)
					continue
				}
			} else {
				return nil, fmt.Errorf("gitleaks failed for %s: %w", target, err)
			}
		}

		outputData, err := os.ReadFile(outputFile)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("failed to read gitleaks output: %w", err)
		}

		var results []GitleaksResult
		if err := json.Unmarshal(outputData, &results); err != nil {
			s.logger.Warn("Failed to parse Gitleaks output for %s: %v", target, err)
			continue
		}

		for _, r := range results {
			finding := gitleaksResultToFinding(r, project.ID)
			allFindings = append(allFindings, finding)
		}
	}

	s.logger.Debug("Gitleaks found %d secrets", len(allFindings))
	return allFindings, nil
}

// Scan implements the legacy Scanner interface.
func (s *GitleaksScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	targets, ok := target.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Gitleaks: %T", target)
	}
	return s.ScanVulnerabilities(ctx, project, targets, ScanOptions{Extra: options})
}

// gitleaksResultToFinding converts a Gitleaks result to a Finding.
func gitleaksResultToFinding(r GitleaksResult, projectID string) *models.Finding {
	// Redact the actual secret value for safety
	redactedSecret := redactSecret(r.Secret)

	details := fmt.Sprintf("Rule: %s\nFile: %s:%d\nMatch: %s",
		r.RuleID, r.File, r.StartLine, redactedSecret)
	if r.Commit != "" {
		details += fmt.Sprintf("\nCommit: %s", r.Commit)
	}
	if r.Author != "" {
		details += fmt.Sprintf("\nAuthor: %s", r.Author)
	}

	return &models.Finding{
		ProjectID:   projectID,
		Type:        models.FindingTypeVulnerability,
		Title:       fmt.Sprintf("Secret Detected: %s", r.Description),
		Description: fmt.Sprintf("Gitleaks detected a potential secret (%s) in %s at line %d.", r.Description, r.File, r.StartLine),
		Details:     details,
		Severity:    models.SeverityHigh,
		FoundBy:     "gitleaks",
		Status:      models.FindingStatusNew,
		AffectedAssets: []string{r.File},
	}
}

// redactSecret masks a secret value, showing only the first and last 2 characters.
func redactSecret(secret string) string {
	if len(secret) <= 8 {
		return strings.Repeat("*", len(secret))
	}
	return secret[:2] + strings.Repeat("*", len(secret)-4) + secret[len(secret)-2:]
}
