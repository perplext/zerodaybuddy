package report

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockSARIFStore implements SARIFStore for testing.
type mockSARIFStore struct {
	mock.Mock
}

func (m *mockSARIFStore) GetProject(ctx context.Context, id string) (*models.Project, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Project), args.Error(1)
}

func (m *mockSARIFStore) ListFindings(ctx context.Context, projectID string) ([]*models.Finding, error) {
	args := m.Called(ctx, projectID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*models.Finding), args.Error(1)
}

func TestGenerateSARIF_WithFindings(t *testing.T) {
	store := new(mockSARIFStore)
	project := &models.Project{ID: "proj-1", Name: "Test Project"}
	findings := []*models.Finding{
		{
			ID:       "f1",
			Title:    "SQL Injection",
			Description: "SQL injection in login form",
			Severity: models.SeverityCritical,
			CWE:      "CWE-89",
			URL:      "https://example.com/login",
			CVSS:     9.8,
		},
		{
			ID:       "f2",
			Title:    "XSS in Search",
			Description: "Reflected XSS in search parameter",
			Severity: models.SeverityHigh,
			CWE:      "CWE-79",
			URL:      "https://example.com/search",
		},
	}

	store.On("GetProject", mock.Anything, "proj-1").Return(project, nil)
	store.On("ListFindings", mock.Anything, "proj-1").Return(findings, nil)

	result, err := GenerateSARIF(context.Background(), store, "proj-1")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)

	// Validate SARIF structure
	var sarif map[string]interface{}
	err = json.Unmarshal([]byte(result), &sarif)
	assert.NoError(t, err)
	assert.Equal(t, "2.1.0", sarif["version"])

	runs := sarif["runs"].([]interface{})
	assert.Len(t, runs, 1)

	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	assert.Len(t, results, 2)

	store.AssertExpectations(t)
}

func TestGenerateSARIF_EmptyFindings(t *testing.T) {
	store := new(mockSARIFStore)
	project := &models.Project{ID: "proj-1", Name: "Test"}

	store.On("GetProject", mock.Anything, "proj-1").Return(project, nil)
	store.On("ListFindings", mock.Anything, "proj-1").Return([]*models.Finding{}, nil)

	result, err := GenerateSARIF(context.Background(), store, "proj-1")
	assert.NoError(t, err)
	assert.NotEmpty(t, result)

	var sarif map[string]interface{}
	err = json.Unmarshal([]byte(result), &sarif)
	assert.NoError(t, err)

	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	assert.Empty(t, results)
}

func TestGenerateSARIF_DuplicateCWERules(t *testing.T) {
	store := new(mockSARIFStore)
	project := &models.Project{ID: "proj-1", Name: "Test"}
	// Two findings with the same CWE — should only create one rule
	findings := []*models.Finding{
		{ID: "f1", Title: "SQLi 1", Description: "desc1", Severity: models.SeverityHigh, CWE: "CWE-89", Type: models.FindingTypeVulnerability},
		{ID: "f2", Title: "SQLi 2", Description: "desc2", Severity: models.SeverityHigh, CWE: "CWE-89", Type: models.FindingTypeVulnerability},
	}

	store.On("GetProject", mock.Anything, "proj-1").Return(project, nil)
	store.On("ListFindings", mock.Anything, "proj-1").Return(findings, nil)

	result, err := GenerateSARIF(context.Background(), store, "proj-1")
	assert.NoError(t, err)

	var sarif map[string]interface{}
	json.Unmarshal([]byte(result), &sarif)
	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})

	// Should have 2 results but only 1 rule
	results := run["results"].([]interface{})
	assert.Len(t, results, 2)

	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	rules := driver["rules"].([]interface{})
	assert.Len(t, rules, 1, "duplicate CWE should create only one rule")
}

func TestGenerateSARIF_ProjectNotFound(t *testing.T) {
	store := new(mockSARIFStore)
	store.On("GetProject", mock.Anything, "missing").Return(nil, fmt.Errorf("not found"))

	_, err := GenerateSARIF(context.Background(), store, "missing")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get project")
}

func TestRuleIDFromFinding(t *testing.T) {
	tests := []struct {
		name    string
		finding *models.Finding
		want    string
	}{
		{"with CWE", &models.Finding{CWE: "CWE-89", Type: models.FindingTypeVulnerability}, "CWE-89"},
		{"without CWE", &models.Finding{Type: models.FindingTypeVulnerability}, "ZDB-vulnerability"},
		{"without CWE, different type", &models.Finding{Type: "misconfiguration"}, "ZDB-misconfiguration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleIDFromFinding(tt.finding)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSarifLevel(t *testing.T) {
	tests := []struct {
		severity models.FindingSeverity
		want     string
	}{
		{models.SeverityCritical, "error"},
		{models.SeverityHigh, "error"},
		{models.SeverityMedium, "warning"},
		{models.SeverityLow, "note"},
		{models.SeverityInfo, "note"},
		{"unknown", "none"},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := sarifLevel(tt.severity)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSecuritySeverity(t *testing.T) {
	tests := []struct {
		name string
		finding *models.Finding
		want float64
	}{
		{"with CVSS score", &models.Finding{CVSS: 7.5, Severity: models.SeverityHigh}, 7.5},
		{"critical no CVSS", &models.Finding{Severity: models.SeverityCritical}, 9.5},
		{"high no CVSS", &models.Finding{Severity: models.SeverityHigh}, 8.0},
		{"medium no CVSS", &models.Finding{Severity: models.SeverityMedium}, 5.5},
		{"low no CVSS", &models.Finding{Severity: models.SeverityLow}, 2.5},
		{"info no CVSS", &models.Finding{Severity: models.SeverityInfo}, 0.5},
		{"unknown no CVSS", &models.Finding{Severity: "unknown"}, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := securitySeverity(tt.finding)
			assert.Equal(t, tt.want, got)
		})
	}
}
