package recon

import (
	"context"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestNewKatanaScanner(t *testing.T) {
	cfg := config.ToolsConfig{KatanaPath: "/usr/bin/katana"}
	logger := utils.NewLogger("", true)
	scanner := NewKatanaScanner(cfg, logger)

	assert.NotNil(t, scanner)
	assert.Equal(t, cfg, scanner.config)
}

func TestKatanaScanner_Name(t *testing.T) {
	scanner := &KatanaScanner{}
	assert.Equal(t, "katana", scanner.Name())
}

func TestKatanaScanner_Description(t *testing.T) {
	scanner := &KatanaScanner{}
	assert.Equal(t, "Crawls websites to discover endpoints", scanner.Description())
}

func TestKatanaScanner_Scan_InvalidTargetType(t *testing.T) {
	scanner := NewKatanaScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	invalidTargets := []interface{}{
		123,
		"not-a-slice",
		nil,
	}

	for _, target := range invalidTargets {
		result, err := scanner.Scan(context.Background(), project, target, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid target type for Katana")
		assert.Nil(t, result)
	}
}

func TestKatanaScanner_DiscoverEndpoints_EmptyInput(t *testing.T) {
	scanner := NewKatanaScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := getTestProjectWithScope()

	endpoints, err := scanner.DiscoverEndpoints(context.Background(), project, []string{}, ScanOptions{})
	assert.NoError(t, err)
	assert.Nil(t, endpoints)
}

func TestKatanaResultToEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		result    KatanaResult
		projectID string
		wantURL   string
		wantMethod string
	}{
		{
			name: "full result",
			result: KatanaResult{
				URL:    "https://example.com/api/v1/users",
				Method: "POST",
				Status: 200,
			},
			projectID:  "proj-123",
			wantURL:    "https://example.com/api/v1/users",
			wantMethod: "POST",
		},
		{
			name: "empty method defaults to GET",
			result: KatanaResult{
				URL:    "https://example.com/page",
				Method: "",
				Status: 301,
			},
			projectID:  "proj-456",
			wantURL:    "https://example.com/page",
			wantMethod: "GET",
		},
		{
			name: "zero status",
			result: KatanaResult{
				URL:    "https://example.com/test",
				Method: "GET",
				Status: 0,
			},
			projectID:  "proj-789",
			wantURL:    "https://example.com/test",
			wantMethod: "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep := katanaResultToEndpoint(tt.result, tt.projectID)
			assert.Equal(t, tt.wantURL, ep.URL)
			assert.Equal(t, tt.wantMethod, ep.Method)
			assert.Equal(t, tt.projectID, ep.ProjectID)
			assert.Equal(t, "katana", ep.FoundBy)
		})
	}
}

func TestKatanaScanner_DiscoverEndpoints_OutOfScope(t *testing.T) {
	scanner := NewKatanaScanner(config.ToolsConfig{}, utils.NewLogger("", true))
	project := &models.Project{
		ID:   "test-project",
		Name: "test-project",
		Scope: models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
			},
		},
	}

	// Out-of-scope URL — should be skipped without error
	endpoints, err := scanner.DiscoverEndpoints(context.Background(), project, []string{"https://evil.com"}, ScanOptions{})
	assert.NoError(t, err)
	assert.Empty(t, endpoints)
}

func TestKatanaScanner_ConfigPathFallback(t *testing.T) {
	tests := []struct {
		name   string
		config config.ToolsConfig
	}{
		{"custom path", config.ToolsConfig{KatanaPath: "/custom/katana"}},
		{"default path", config.ToolsConfig{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewKatanaScanner(tt.config, utils.NewLogger("", true))
			assert.NotNil(t, scanner)
		})
	}
}
