package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// TrivyScanner implements VulnerabilityScanner for Trivy container image scanning.
type TrivyScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewTrivyScanner creates a new Trivy scanner.
func NewTrivyScanner(config config.ToolsConfig, logger *utils.Logger) *TrivyScanner {
	return &TrivyScanner{
		config: config,
		logger: logger,
	}
}

func (s *TrivyScanner) Name() string        { return "trivy" }
func (s *TrivyScanner) Description() string  { return "Scans container images for vulnerabilities" }

// TrivyOutput represents the top-level Trivy JSON output.
type TrivyOutput struct {
	Results []TrivyResult `json:"Results"`
}

// TrivyResult represents a single target's scan results.
type TrivyResult struct {
	Target          string            `json:"Target"`
	Class           string            `json:"Class"`
	Type            string            `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

// TrivyVulnerability represents a single vulnerability found by Trivy.
type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	References       []string `json:"References"`
	CVSS             map[string]TrivyCVSS `json:"CVSS"`
}

// TrivyCVSS represents CVSS scoring from a specific source.
type TrivyCVSS struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}

// ScanVulnerabilities scans container images for vulnerabilities.
func (s *TrivyScanner) ScanVulnerabilities(ctx context.Context, project *models.Project, targets []string, opts ScanOptions) ([]*models.Finding, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	s.logger.Debug("Starting Trivy scan for %d targets", len(targets))

	trivyPath := s.config.TrivyPath
	if trivyPath == "" {
		trivyPath = "trivy"
	}

	var allFindings []*models.Finding

	for _, target := range targets {
		if !project.Scope.IsInScope(models.AssetTypeContainer, target) {
			s.logger.Debug("Skipping out-of-scope target: %s", target)
			continue
		}

		args := []string{
			"image",
			"--format", "json",
			"--quiet",
			target,
		}

		if opts.Severity != "" {
			if validated, err := validateTrivySeverity(opts.Severity); err != nil {
				return nil, fmt.Errorf("invalid severity option: %w", err)
			} else {
				args = append(args, "--severity", validated)
			}
		}

		s.logger.Debug("Running Trivy: %s %v", trivyPath, args)
		cmd := exec.CommandContext(ctx, trivyPath, args...)
		output, err := cmd.Output()
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				s.logger.Warn("Trivy returned non-zero exit: %s", exitErr.Stderr)
			} else {
				return nil, fmt.Errorf("trivy failed for %s: %w", target, err)
			}
		}

		if len(output) == 0 {
			continue
		}

		var trivyOutput TrivyOutput
		if err := json.Unmarshal(output, &trivyOutput); err != nil {
			s.logger.Warn("Failed to parse Trivy output for %s: %v", target, err)
			continue
		}

		for _, result := range trivyOutput.Results {
			for _, vuln := range result.Vulnerabilities {
				finding := trivyVulnToFinding(vuln, result.Target, project.ID)
				allFindings = append(allFindings, finding)
			}
		}
	}

	s.logger.Debug("Trivy found %d vulnerabilities", len(allFindings))
	return allFindings, nil
}

// Scan implements the legacy Scanner interface.
func (s *TrivyScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	targets, ok := target.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Trivy: %T", target)
	}
	return s.ScanVulnerabilities(ctx, project, targets, ScanOptions{Extra: options})
}

// trivyVulnToFinding converts a Trivy vulnerability to a Finding.
func trivyVulnToFinding(vuln TrivyVulnerability, target, projectID string) *models.Finding {
	title := vuln.Title
	if title == "" {
		title = fmt.Sprintf("%s in %s", vuln.VulnerabilityID, vuln.PkgName)
	}

	details := fmt.Sprintf("Package: %s\nInstalled: %s", vuln.PkgName, vuln.InstalledVersion)
	if vuln.FixedVersion != "" {
		details += fmt.Sprintf("\nFixed in: %s", vuln.FixedVersion)
	}

	finding := &models.Finding{
		ProjectID:   projectID,
		Type:        models.FindingTypeVulnerability,
		Title:       title,
		Description: vuln.Description,
		Details:     details,
		Severity:    models.FindingSeverity(strings.ToLower(vuln.Severity)),
		References:  append([]string{vuln.VulnerabilityID}, vuln.References...),
		FoundBy:     "trivy",
		Status:      models.FindingStatusNew,
		AffectedAssets: []string{target},
	}

	// Extract CVSS from the first available source
	for _, cvss := range vuln.CVSS {
		if cvss.V3Score > 0 {
			finding.CVSS = cvss.V3Score
			finding.CVSSVector = cvss.V3Vector
			finding.CVSSVersion = "3.1"
			break
		}
	}

	return finding
}

// allowedTrivySeverities is the set of valid Trivy severity levels.
var allowedTrivySeverities = map[string]bool{
	"unknown": true, "low": true, "medium": true, "high": true, "critical": true,
}

// validateTrivySeverity validates a comma-separated list of severity levels.
func validateTrivySeverity(severity string) (string, error) {
	var valid []string
	for _, s := range strings.Split(severity, ",") {
		s = strings.TrimSpace(strings.ToUpper(s))
		if s == "" {
			continue
		}
		if !allowedTrivySeverities[strings.ToLower(s)] {
			return "", fmt.Errorf("unknown severity level %q", s)
		}
		valid = append(valid, s)
	}
	if len(valid) == 0 {
		return "", fmt.Errorf("no valid severity levels specified")
	}
	return strings.Join(valid, ","), nil
}
