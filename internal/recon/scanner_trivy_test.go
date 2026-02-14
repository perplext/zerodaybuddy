package recon

import (
	"context"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewTrivyScanner(t *testing.T) {
	cfg := config.ToolsConfig{TrivyPath: "/usr/bin/trivy"}
	logger := utils.NewLogger("", true)
	scanner := NewTrivyScanner(cfg, logger)

	assert.NotNil(t, scanner)
	assert.Equal(t, cfg, scanner.config)
}

func TestTrivyScanner_Name(t *testing.T) {
	scanner := &TrivyScanner{}
	assert.Equal(t, "trivy", scanner.Name())
}

func TestTrivyScanner_Description(t *testing.T) {
	scanner := &TrivyScanner{}
	assert.Equal(t, "Scans container images for vulnerabilities", scanner.Description())
}

func TestTrivyScanner_Scan_InvalidTargetType(t *testing.T) {
	scanner := NewTrivyScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	invalidTargets := []interface{}{
		123,
		"not-a-slice",
		nil,
	}

	for _, target := range invalidTargets {
		result, err := scanner.Scan(context.Background(), project, target, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid target type for Trivy")
		assert.Nil(t, result)
	}
}

func TestTrivyScanner_ScanVulnerabilities_EmptyInput(t *testing.T) {
	scanner := NewTrivyScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	findings, err := scanner.ScanVulnerabilities(context.Background(), project, []string{}, ScanOptions{})
	assert.NoError(t, err)
	assert.Nil(t, findings)
}

func TestTrivyVulnToFinding(t *testing.T) {
	tests := []struct {
		name      string
		vuln      TrivyVulnerability
		target    string
		projectID string
	}{
		{
			name: "full vulnerability with title",
			vuln: TrivyVulnerability{
				VulnerabilityID:  "CVE-2021-44228",
				PkgName:          "log4j-core",
				InstalledVersion: "2.14.1",
				FixedVersion:     "2.17.0",
				Severity:         "CRITICAL",
				Title:            "Log4j Remote Code Execution",
				Description:      "Apache Log4j2 JNDI vulnerability",
				References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
				CVSS: map[string]TrivyCVSS{
					"nvd": {V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", V3Score: 10.0},
				},
			},
			target:    "alpine:3.18",
			projectID: "proj-123",
		},
		{
			name: "vulnerability without title",
			vuln: TrivyVulnerability{
				VulnerabilityID:  "CVE-2022-12345",
				PkgName:          "openssl",
				InstalledVersion: "1.1.1k",
				Severity:         "HIGH",
			},
			target:    "nginx:latest",
			projectID: "proj-456",
		},
		{
			name: "vulnerability without fixed version",
			vuln: TrivyVulnerability{
				VulnerabilityID:  "CVE-2023-99999",
				PkgName:          "curl",
				InstalledVersion: "7.88.0",
				FixedVersion:     "",
				Severity:         "MEDIUM",
				Title:            "Curl Buffer Overflow",
			},
			target:    "ubuntu:22.04",
			projectID: "proj-789",
		},
		{
			name: "vulnerability with no CVSS",
			vuln: TrivyVulnerability{
				VulnerabilityID:  "CVE-2023-11111",
				PkgName:          "zlib",
				InstalledVersion: "1.2.11",
				Severity:         "LOW",
				Title:            "Low severity zlib issue",
			},
			target:    "debian:11",
			projectID: "proj-abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := trivyVulnToFinding(tt.vuln, tt.target, tt.projectID)
			assert.Equal(t, tt.projectID, finding.ProjectID)
			assert.Equal(t, models.FindingTypeVulnerability, finding.Type)
			assert.Equal(t, "trivy", finding.FoundBy)
			assert.Equal(t, models.FindingStatusNew, finding.Status)
			assert.Contains(t, finding.AffectedAssets, tt.target)

			// Title: uses vuln.Title if present, otherwise "CVE in PkgName"
			if tt.vuln.Title != "" {
				assert.Equal(t, tt.vuln.Title, finding.Title)
			} else {
				assert.Contains(t, finding.Title, tt.vuln.VulnerabilityID)
				assert.Contains(t, finding.Title, tt.vuln.PkgName)
			}

			// Details: should contain package and version info
			assert.Contains(t, finding.Details, tt.vuln.PkgName)
			assert.Contains(t, finding.Details, tt.vuln.InstalledVersion)
			if tt.vuln.FixedVersion != "" {
				assert.Contains(t, finding.Details, tt.vuln.FixedVersion)
			}

			// References: first element should be the CVE ID
			assert.NotEmpty(t, finding.References)
			assert.Equal(t, tt.vuln.VulnerabilityID, finding.References[0])

			// CVSS: should be extracted from first source
			if len(tt.vuln.CVSS) > 0 {
				for _, cvss := range tt.vuln.CVSS {
					if cvss.V3Score > 0 {
						assert.Equal(t, cvss.V3Score, finding.CVSS)
						assert.Equal(t, cvss.V3Vector, finding.CVSSVector)
						assert.Equal(t, "3.1", finding.CVSSVersion)
						break
					}
				}
			} else {
				assert.Zero(t, finding.CVSS)
			}

			// Severity mapping
			assert.Equal(t, models.FindingSeverity(finding.Severity), finding.Severity)
		})
	}
}

func TestValidateTrivySeverity(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"single valid", "high", "HIGH", false},
		{"multiple valid", "low,medium,high", "LOW,MEDIUM,HIGH", false},
		{"all levels", "unknown,low,medium,high,critical", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL", false},
		{"with spaces", "low, medium, high", "LOW,MEDIUM,HIGH", false},
		{"invalid level", "extreme", "", true},
		{"mixed valid/invalid", "low,extreme", "", true},
		{"empty string", "", "", true},
		{"only commas", ",,", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateTrivySeverity(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTrivyScanner_ConfigPathFallback(t *testing.T) {
	tests := []struct {
		name   string
		config config.ToolsConfig
	}{
		{"custom path", config.ToolsConfig{TrivyPath: "/custom/trivy"}},
		{"default path", config.ToolsConfig{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewTrivyScanner(tt.config, utils.NewLogger("", true))
			assert.NotNil(t, scanner)
		})
	}
}

func TestTrivyOutput_Structure(t *testing.T) {
	// Test that the TrivyOutput struct can hold multiple results
	output := TrivyOutput{
		Results: []TrivyResult{
			{
				Target: "alpine:3.18",
				Class:  "os-pkgs",
				Type:   "alpine",
				Vulnerabilities: []TrivyVulnerability{
					{VulnerabilityID: "CVE-2021-1", Severity: "HIGH"},
					{VulnerabilityID: "CVE-2021-2", Severity: "LOW"},
				},
			},
			{
				Target:          "node_modules/",
				Class:           "lang-pkgs",
				Type:            "npm",
				Vulnerabilities: nil,
			},
		},
	}

	assert.Len(t, output.Results, 2)
	assert.Len(t, output.Results[0].Vulnerabilities, 2)
	assert.Empty(t, output.Results[1].Vulnerabilities)
}
