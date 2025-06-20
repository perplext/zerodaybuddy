//go:build integration

package recon

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAmassExecutor helps test amass commands
type mockAmassExecutor struct {
	output string
	err    error
}

func TestAmassScanner_BasicInfo(t *testing.T) {
	scanner := NewAmassScanner(config.ToolsConfig{}, utils.NewLogger("", false))
	
	assert.Equal(t, "amass", scanner.Name())
	assert.Equal(t, "Discovers subdomains using Amass", scanner.Description())
}

func TestAmassScanner_Scan(t *testing.T) {
	if os.Getenv("GO_TEST_SUBPROCESS") == "1" {
		// This is the subprocess
		switch os.Getenv("TEST_CASE") {
		case "success":
			// Simulate successful amass output
			output := `sub1.example.com
sub2.example.com
api.example.com
www.example.com`
			os.Stdout.Write([]byte(output))
		case "error":
			os.Exit(1)
		case "mixed_output":
			// Simulate output with some non-domain lines
			output := `[*] Starting enumeration...
sub1.example.com
192.168.1.1
sub2.example.com
[*] Found 2 subdomains`
			os.Stdout.Write([]byte(output))
		}
		os.Exit(0)
	}

	tests := []struct {
		name           string
		target         interface{}
		testCase       string
		expectedError  bool
		expectedCount  int
		inScope        []string
		outScope       []string
	}{
		{
			name:          "successful scan",
			target:        "example.com",
			testCase:      "success",
			expectedError: false,
			expectedCount: 4,
			inScope:       []string{"*.example.com"},
		},
		{
			name:          "invalid target type",
			target:        123,
			expectedError: true,
		},
		{
			name:          "command error",
			target:        "example.com",
			testCase:      "error",
			expectedError: true,
		},
		{
			name:          "mixed output parsing",
			target:        "example.com",
			testCase:      "mixed_output",
			expectedError: false,
			expectedCount: 2,
			inScope:       []string{"*.example.com"},
		},
		{
			name:          "scope filtering",
			target:        "example.com",
			testCase:      "success",
			expectedError: false,
			expectedCount: 2, // Only sub1 and sub2 should be in scope
			inScope:       []string{"sub1.example.com", "sub2.example.com"},
			outScope:      []string{"api.example.com", "www.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create scanner
			logger := utils.NewLogger("", false)
			scanner := NewAmassScanner(config.ToolsConfig{}, logger)

			// Create project with scope
			project := &models.Project{
				Name: "test-project",
				Scope: models.Scope{
					InScope:    makeAssets(models.AssetTypeDomain, tt.inScope),
					OutOfScope: makeAssets(models.AssetTypeDomain, tt.outScope),
				},
			}

			// Skip if invalid target type
			if _, ok := tt.target.(string); !ok && tt.expectedError {
				result, err := scanner.Scan(context.Background(), project, tt.target, nil)
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), "invalid target type")
				return
			}

			// Override exec.CommandContext for testing
			oldCommandContext := execCommandContext
			defer func() { execCommandContext = oldCommandContext }()
			
			execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestAmassScanner_Scan", "--"}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = append(os.Environ(), 
					"GO_TEST_SUBPROCESS=1",
					"TEST_CASE="+tt.testCase,
				)
				return cmd
			}

			// Run scan
			result, err := scanner.Scan(context.Background(), project, tt.target, nil)

			// Check results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				subdomains, ok := result.([]string)
				require.True(t, ok, "result should be []string")
				assert.Len(t, subdomains, tt.expectedCount)
			}
		})
	}
}

func TestAmassScanner_ScanWithContext(t *testing.T) {
	if os.Getenv("GO_TEST_SUBPROCESS") == "1" {
		// Sleep forever to test context cancellation
		select {}
	}

	// Create scanner
	logger := utils.NewLogger("", false)
	scanner := NewAmassScanner(config.ToolsConfig{}, logger)

	// Create project
	project := &models.Project{
		Name: "test-project",
		Scope: models.Scope{
			InScope: makeAssets(models.AssetTypeDomain, []string{"*.example.com"}),
		},
	}

	// Override exec.CommandContext
	oldCommandContext := execCommandContext
	defer func() { execCommandContext = oldCommandContext }()
	
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=TestAmassScanner_ScanWithContext", "--"}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = append(os.Environ(), "GO_TEST_SUBPROCESS=1")
		return cmd
	}

	// Create context that we'll cancel
	ctx, cancel := context.WithCancel(context.Background())
	
	// Start scan in goroutine
	done := make(chan struct{})
	var err error
	go func() {
		_, err = scanner.Scan(ctx, project, "example.com", nil)
		close(done)
	}()

	// Cancel context immediately
	cancel()

	// Wait for scan to complete
	<-done

	// Should have context error
	assert.Error(t, err)
}

