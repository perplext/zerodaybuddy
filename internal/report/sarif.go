package report

import (
	"bytes"
	"context"
	"fmt"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/perplext/zerodaybuddy/pkg/models"
)

// SARIFStore defines the storage methods needed for SARIF generation.
type SARIFStore interface {
	GetProject(ctx context.Context, id string) (*models.Project, error)
	ListFindings(ctx context.Context, projectID string) ([]*models.Finding, error)
}

// GenerateSARIF generates a SARIF v2.1.0 report from project findings.
func GenerateSARIF(ctx context.Context, store SARIFStore, projectID string) (string, error) {
	project, err := store.GetProject(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("failed to get project: %w", err)
	}

	findings, err := store.ListFindings(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("failed to list findings: %w", err)
	}

	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return "", fmt.Errorf("failed to create SARIF report: %w", err)
	}

	run := sarif.NewRunWithInformationURI("zerodaybuddy", "https://github.com/perplext/zerodaybuddy")
	run.Tool.Driver.WithVersion("0.1.0")
	run.Tool.Driver.WithSemanticVersion("0.1.0")

	seenRules := make(map[string]bool)

	for _, f := range findings {
		ruleID := ruleIDFromFinding(f)

		// Add rule only if not already present
		if !seenRules[ruleID] {
			seenRules[ruleID] = true
			rule := run.AddRule(ruleID).
				WithDescription(f.Description).
				WithShortDescription(&sarif.MultiformatMessageString{Text: &f.Title})

			if f.CWE != "" {
				rule.Properties = sarif.Properties{
					"cwe": f.CWE,
				}
			}
		}

		// Map severity to SARIF level
		level := sarifLevel(f.Severity)

		// Create result
		result := sarif.NewRuleResult(ruleID).
			WithLevel(level).
			WithMessage(sarif.NewTextMessage(f.Title))

		// Add security-severity property for GitHub integration
		secSeverity := securitySeverity(f)
		result.Properties = sarif.Properties{
			"security-severity": fmt.Sprintf("%.1f", secSeverity),
		}

		// Add location if URL is available
		if f.URL != "" {
			location := sarif.NewLocationWithPhysicalLocation(
				sarif.NewPhysicalLocation().
					WithArtifactLocation(sarif.NewSimpleArtifactLocation(f.URL)),
			)
			result.WithLocations([]*sarif.Location{location})
		}

		run.AddResult(result)
	}

	report.AddRun(run)

	// Serialize
	var buf bytes.Buffer
	if err := report.Write(&buf); err != nil {
		return "", fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	_ = project // used for validation above
	return buf.String(), nil
}

// ruleIDFromFinding generates a stable rule ID from a finding.
func ruleIDFromFinding(f *models.Finding) string {
	if f.CWE != "" {
		return f.CWE
	}
	return fmt.Sprintf("ZDB-%s", f.Type)
}

// sarifLevel maps FindingSeverity to SARIF level strings.
func sarifLevel(severity models.FindingSeverity) string {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow, models.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

// securitySeverity returns a numeric security-severity value for GitHub integration.
// Range: 0.0-10.0 mapping to low (0.1-3.9), medium (4.0-6.9), high (7.0-8.9), critical (9.0+).
func securitySeverity(f *models.Finding) float64 {
	if f.CVSS > 0 {
		return f.CVSS
	}
	switch f.Severity {
	case models.SeverityCritical:
		return 9.5
	case models.SeverityHigh:
		return 8.0
	case models.SeverityMedium:
		return 5.5
	case models.SeverityLow:
		return 2.5
	case models.SeverityInfo:
		return 0.5
	default:
		return 0.0
	}
}
