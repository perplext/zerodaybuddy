package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReportTypes(t *testing.T) {
	// Test that report types have the expected values
	assert.Equal(t, ReportType("project"), ReportTypeProject)
	assert.Equal(t, ReportType("finding"), ReportTypeFinding)
}

func TestReportTypeUsage(t *testing.T) {
	// Test using report types in various contexts
	tests := []struct {
		name       string
		reportType ReportType
		expected   string
	}{
		{
			name:       "project report type",
			reportType: ReportTypeProject,
			expected:   "project",
		},
		{
			name:       "finding report type",
			reportType: ReportTypeFinding,
			expected:   "finding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Convert to string
			result := string(tt.reportType)
			assert.Equal(t, tt.expected, result)
			
			// Compare with ReportType
			assert.Equal(t, tt.reportType, ReportType(tt.expected))
		})
	}
}

func TestReportTypeInStructure(t *testing.T) {
	// Test that ReportType can be used in Report structure
	// even though it's not currently part of the Report struct
	type ExtendedReport struct {
		Report
		Type ReportType `json:"type"`
	}

	report := ExtendedReport{
		Report: Report{
			ID:        "report-001",
			ProjectID: "proj-001",
			Title:     "Project Summary Report",
			Format:    "pdf",
			Content:   "Project report content",
		},
		Type: ReportTypeProject,
	}

	assert.Equal(t, ReportTypeProject, report.Type)
	assert.Equal(t, "project", string(report.Type))

	// Test with finding report
	findingReport := ExtendedReport{
		Report: Report{
			ID:        "report-002",
			ProjectID: "proj-001",
			FindingID: "finding-001",
			Title:     "SQL Injection Finding Report",
			Format:    "markdown",
			Content:   "Finding report content",
		},
		Type: ReportTypeFinding,
	}

	assert.Equal(t, ReportTypeFinding, findingReport.Type)
	assert.Equal(t, "finding", string(findingReport.Type))
}

func TestReportTypeValidation(t *testing.T) {
	// Test validation logic that could be added for report types
	isValidReportType := func(rt ReportType) bool {
		switch rt {
		case ReportTypeProject, ReportTypeFinding:
			return true
		default:
			return false
		}
	}

	tests := []struct {
		name     string
		input    ReportType
		expected bool
	}{
		{
			name:     "valid project type",
			input:    ReportTypeProject,
			expected: true,
		},
		{
			name:     "valid finding type",
			input:    ReportTypeFinding,
			expected: true,
		},
		{
			name:     "invalid type",
			input:    ReportType("invalid"),
			expected: false,
		},
		{
			name:     "empty type",
			input:    ReportType(""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidReportType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}