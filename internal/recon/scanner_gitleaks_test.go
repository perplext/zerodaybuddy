package recon

import (
	"context"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewGitleaksScanner(t *testing.T) {
	cfg := config.ToolsConfig{GitleaksPath: "/usr/bin/gitleaks"}
	logger := utils.NewLogger("", true)
	scanner := NewGitleaksScanner(cfg, logger)

	assert.NotNil(t, scanner)
	assert.Equal(t, cfg, scanner.config)
}

func TestGitleaksScanner_Name(t *testing.T) {
	scanner := &GitleaksScanner{}
	assert.Equal(t, "gitleaks", scanner.Name())
}

func TestGitleaksScanner_Description(t *testing.T) {
	scanner := &GitleaksScanner{}
	assert.Equal(t, "Detects secrets and credentials in code and repositories", scanner.Description())
}

func TestGitleaksScanner_Scan_InvalidTargetType(t *testing.T) {
	scanner := NewGitleaksScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	invalidTargets := []interface{}{
		123,
		"not-a-slice",
		nil,
	}

	for _, target := range invalidTargets {
		result, err := scanner.Scan(context.Background(), project, target, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid target type for Gitleaks")
		assert.Nil(t, result)
	}
}

func TestGitleaksScanner_ScanVulnerabilities_EmptyInput(t *testing.T) {
	scanner := NewGitleaksScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	findings, err := scanner.ScanVulnerabilities(context.Background(), project, []string{}, ScanOptions{})
	assert.NoError(t, err)
	assert.Nil(t, findings)
}

func TestGitleaksResultToFinding(t *testing.T) {
	tests := []struct {
		name      string
		result    GitleaksResult
		projectID string
	}{
		{
			name: "full result",
			result: GitleaksResult{
				Description: "AWS Access Key",
				StartLine:   42,
				EndLine:     42,
				Match:       "AKIA1234567890ABCDEF",
				Secret:      "AKIA1234567890ABCDEF",
				File:        "config/credentials.yaml",
				Commit:      "abc123def456",
				Author:      "developer@example.com",
				RuleID:      "aws-access-key-id",
				Fingerprint: "fp-123",
			},
			projectID: "proj-123",
		},
		{
			name: "minimal result",
			result: GitleaksResult{
				Description: "Generic API Key",
				StartLine:   10,
				Secret:      "abc12345",
				File:        "main.go",
				RuleID:      "generic-api-key",
			},
			projectID: "proj-456",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := gitleaksResultToFinding(tt.result, tt.projectID)
			assert.Equal(t, tt.projectID, finding.ProjectID)
			assert.Equal(t, models.FindingTypeVulnerability, finding.Type)
			assert.Contains(t, finding.Title, tt.result.Description)
			assert.Equal(t, models.SeverityHigh, finding.Severity)
			assert.Equal(t, "gitleaks", finding.FoundBy)
			assert.Equal(t, models.FindingStatusNew, finding.Status)
			assert.Contains(t, finding.AffectedAssets, tt.result.File)
			// Details should contain rule info
			assert.Contains(t, finding.Details, tt.result.RuleID)
			assert.Contains(t, finding.Details, tt.result.File)
		})
	}
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		name     string
		secret   string
		expected string
	}{
		{"short secret", "abc", "***"},
		{"8-char secret", "12345678", "********"},
		{"long secret", "AKIA1234567890ABCDEF", "AK****************EF"},
		{"empty secret", "", ""},
		{"9-char secret", "123456789", "12*****89"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactSecret(tt.secret)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGitleaksScanner_ConfigPathFallback(t *testing.T) {
	tests := []struct {
		name   string
		config config.ToolsConfig
	}{
		{"custom path", config.ToolsConfig{GitleaksPath: "/custom/gitleaks"}},
		{"default path", config.ToolsConfig{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewGitleaksScanner(tt.config, utils.NewLogger("", true))
			assert.NotNil(t, scanner)
		})
	}
}
