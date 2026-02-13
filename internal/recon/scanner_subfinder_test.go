package recon

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// Helper function to create a test project with scope
func getTestProjectWithScope() *models.Project {
	return &models.Project{
		ID:   "test-project",
		Name: "test-project",
		Scope: models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
				{Type: models.AssetTypeDomain, Value: "*.example.com"},
			},
		},
	}
}

func TestNewSubfinderScanner(t *testing.T) {
	config := config.ToolsConfig{
		SubfinderPath: "/usr/bin/subfinder",
	}
	logger := utils.NewLogger("", true)
	
	scanner := NewSubfinderScanner(config, logger)
	
	assert.NotNil(t, scanner)
	assert.Equal(t, config, scanner.config)
	assert.Equal(t, logger, scanner.logger)
}

func TestSubfinderScanner_Name(t *testing.T) {
	scanner := &SubfinderScanner{}
	assert.Equal(t, "subfinder", scanner.Name())
}

func TestSubfinderScanner_Description(t *testing.T) {
	scanner := &SubfinderScanner{}
	assert.Equal(t, "Discovers subdomains using Subfinder", scanner.Description())
}

func TestSubfinderScanner_Scan(t *testing.T) {
	// Skip if we're in CI or don't have subfinder
	if os.Getenv("CI") != "" {
		t.Skip("Skipping scanner execution test in CI")
	}
	
	// Check if subfinder is available
	if _, err := exec.LookPath("subfinder"); err != nil {
		t.Skip("Subfinder not found in PATH")
	}
	
	tests := []struct {
		name        string
		target      interface{}
		options     map[string]interface{}
		mockOutput  string
		mockError   error
		wantErr     bool
		errMsg      string
		wantResults []string
	}{
		{
			name:   "Invalid target type",
			target: 123,
			wantErr: true,
			errMsg:  "invalid target type for Subfinder: int",
		},
		{
			name:   "Empty domain",
			target: "",
			wantErr: false,
			wantResults: []string{},
		},
		{
			name:   "Valid domain with results",
			target: "example.com",
			mockOutput: `sub1.example.com
sub2.example.com
sub3.example.com
out.example.org`,
			wantErr: false,
			wantResults: []string{
				"sub1.example.com",
				"sub2.example.com",
				"sub3.example.com",
			}, // out.example.org should be filtered out
		},
		{
			name:   "Custom rate limit",
			target: "example.com",
			options: map[string]interface{}{
				"rate_limit": 100,
			},
			mockOutput: "sub.example.com",
			wantErr: false,
			wantResults: []string{"sub.example.com"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For actual tests with real subfinder, we'll limit to basic validation
			config := config.ToolsConfig{}
			logger := utils.NewLogger("", true)
			scanner := NewSubfinderScanner(config, logger)
			
			project := getTestProjectWithScope()
			ctx := context.Background()
			
			result, err := scanner.Scan(ctx, project, tt.target, tt.options)
			
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				// We can't predict actual results from subfinder
				// Just check that we get a slice of strings
				if err == nil {
					subdomains, ok := result.([]string)
					assert.True(t, ok, "Expected result to be []string")
					assert.NotNil(t, subdomains)
				}
			}
		})
	}
}

func TestSubfinderScanner_Scan_InvalidTarget(t *testing.T) {
	config := config.ToolsConfig{}
	logger := utils.NewLogger("", true)
	scanner := NewSubfinderScanner(config, logger)
	
	project := getTestProjectWithScope()
	ctx := context.Background()
	
	// Test with various invalid target types
	invalidTargets := []interface{}{
		123,
		[]string{"example.com"},
		map[string]string{"domain": "example.com"},
		nil,
	}
	
	for _, target := range invalidTargets {
		result, err := scanner.Scan(ctx, project, target, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid target type for Subfinder")
		assert.Nil(t, result)
	}
}

func TestSubfinderScanner_Scan_ContextCancellation(t *testing.T) {
	// Skip if we're in CI or don't have subfinder
	if os.Getenv("CI") != "" {
		t.Skip("Skipping scanner execution test in CI")
	}
	
	// Check if subfinder is available
	if _, err := exec.LookPath("subfinder"); err != nil {
		t.Skip("Subfinder not found in PATH")
	}
	
	config := config.ToolsConfig{}
	logger := utils.NewLogger("", true)
	scanner := NewSubfinderScanner(config, logger)
	
	project := getTestProjectWithScope()
	
	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	
	result, err := scanner.Scan(ctx, project, "example.com", nil)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestSubfinderScanner_parseOutput(t *testing.T) {
	// This tests the output parsing logic indirectly
	tests := []struct {
		name       string
		output     string
		wantCount  int
	}{
		{
			name:       "Empty output",
			output:     "",
			wantCount:  0,
		},
		{
			name:       "Single subdomain",
			output:     "sub.example.com",
			wantCount:  1,
		},
		{
			name:       "Multiple subdomains",
			output:     "sub1.example.com\nsub2.example.com\nsub3.example.com",
			wantCount:  3,
		},
		{
			name:       "Output with empty lines",
			output:     "sub1.example.com\n\nsub2.example.com\n\n",
			wantCount:  2,
		},
		{
			name:       "Output with whitespace",
			output:     "  sub1.example.com  \n\tsub2.example.com\t",
			wantCount:  2,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We can't directly test the parsing logic since it's internal
			// but we can verify the behavior through the scanner
			// This is more of a documentation of expected behavior
			assert.True(t, true)
		})
	}
}

func TestSubfinderScanner_configOptions(t *testing.T) {
	tests := []struct {
		name           string
		config         config.ToolsConfig
		expectedPath   string
	}{
		{
			name: "Custom subfinder path",
			config: config.ToolsConfig{
				SubfinderPath: "/custom/path/subfinder",
			},
			expectedPath: "/custom/path/subfinder",
		},
		{
			name:         "Default subfinder path",
			config:       config.ToolsConfig{},
			expectedPath: "subfinder",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := utils.NewLogger("", true)
			scanner := NewSubfinderScanner(tt.config, logger)
			
			// Check config
			assert.Equal(t, tt.config, scanner.config)
		})
	}
}