package recon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNaabuScanner_BasicInfo(t *testing.T) {
	scanner := NewNaabuScanner(config.ToolsConfig{}, utils.NewLogger("", false))
	
	assert.Equal(t, "naabu", scanner.Name())
	assert.Equal(t, "Fast port scanner for discovering open ports", scanner.Description())
}

func TestNaabuScanner_Scan(t *testing.T) {
	if os.Getenv("GO_TEST_SUBPROCESS") == "1" {
		// This is the subprocess
		// Parse arguments to find output file
		args := os.Args[1:]
		var outputFile string
		for i, arg := range args {
			if arg == "-o" && i+1 < len(args) {
				outputFile = args[i+1]
				break
			}
		}

		if outputFile == "" {
			os.Exit(1)
		}

		// Generate test output based on test case
		var results []NaabuResult
		switch os.Getenv("TEST_CASE") {
		case "success":
			results = []NaabuResult{
				{Host: "example.com", IP: "93.184.216.34", Port: 80, Proto: "tcp"},
				{Host: "example.com", IP: "93.184.216.34", Port: 443, Proto: "tcp"},
				{Host: "sub.example.com", IP: "93.184.216.35", Port: 22, Proto: "tcp"},
			}
		case "error":
			os.Exit(1)
		case "empty":
			// No results
		case "invalid_json":
			// Write invalid JSON
			os.WriteFile(outputFile, []byte("invalid json\n{broken"), 0644)
			os.Exit(0)
		}

		// Write results to output file
		var output []byte
		for _, result := range results {
			line, _ := json.Marshal(result)
			output = append(output, line...)
			output = append(output, '\n')
		}
		os.WriteFile(outputFile, output, 0644)
		os.Exit(0)
	}

	tests := []struct {
		name          string
		target        interface{}
		testCase      string
		options       map[string]interface{}
		expectedError bool
		expectedCount int
		inScope       []string
		outScope      []string
	}{
		{
			name:          "successful scan",
			target:        []string{"example.com", "sub.example.com"},
			testCase:      "success",
			expectedError: false,
			expectedCount: 3,
			inScope:       []string{"*.example.com"},
		},
		{
			name:          "invalid target type",
			target:        "not-a-slice",
			expectedError: true,
		},
		{
			name:          "empty targets",
			target:        []string{},
			testCase:      "empty",
			expectedError: false,
			expectedCount: 0,
		},
		{
			name:          "command error",
			target:        []string{"example.com"},
			testCase:      "error",
			expectedError: true,
		},
		{
			name:          "invalid json output",
			target:        []string{"example.com"},
			testCase:      "invalid_json",
			expectedError: false,
			expectedCount: 0, // Invalid lines are skipped
		},
		{
			name:          "custom ports option",
			target:        []string{"example.com"},
			testCase:      "success",
			options:       map[string]interface{}{"ports": "80,443,8080"},
			expectedError: false,
			expectedCount: 2, // Only port 80 and 443 from our test data
			inScope:       []string{"*.example.com"},
		},
		{
			name:          "scope filtering",
			target:        []string{"example.com", "sub.example.com"},
			testCase:      "success",
			expectedError: false,
			expectedCount: 2, // Only example.com ports should be in scope
			inScope:       []string{"example.com"},
			outScope:      []string{"sub.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create scanner
			logger := utils.NewLogger("", false)
			scanner := NewNaabuScanner(config.ToolsConfig{
				NaabuPath: "naabu",
			}, logger)

			// Create project with scope
			project := &models.Project{
				Name: "test-project",
				Scope: models.Scope{
					InScope:    makeAssets(models.AssetTypeDomain, tt.inScope),
					OutOfScope: makeAssets(models.AssetTypeDomain, tt.outScope),
				},
			}

			// Skip if invalid target type
			if _, ok := tt.target.([]string); !ok && tt.expectedError {
				result, err := scanner.Scan(context.Background(), project, tt.target, tt.options)
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), "invalid target type")
				return
			}

			// Override exec.CommandContext for testing
			oldCommandContext := execCommandContext
			defer func() { execCommandContext = oldCommandContext }()
			
			execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
				cs := []string{"-test.run=TestNaabuScanner_Scan"}
				cs = append(cs, args...)
				cmd := exec.Command(os.Args[0], cs...)
				cmd.Env = append(os.Environ(), 
					"GO_TEST_SUBPROCESS=1",
					"TEST_CASE="+tt.testCase,
				)
				return cmd
			}

			// Run scan
			result, err := scanner.Scan(context.Background(), project, tt.target, tt.options)

			// Check results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				results, ok := result.([]NaabuResult)
				require.True(t, ok, "result should be []NaabuResult")
				assert.Len(t, results, tt.expectedCount)
			}
		})
	}
}

func TestNaabuScanner_TempFileHandling(t *testing.T) {
	// Create scanner
	logger := utils.NewLogger("", false)
	scanner := NewNaabuScanner(config.ToolsConfig{}, logger)

	// Create project
	project := &models.Project{
		Name: "test-project",
		Scope: models.Scope{
			InScope: makeAssets(models.AssetTypeDomain, []string{"*.example.com"}),
		},
	}

	// Track temp directories created
	var createdDirs []string
	oldMkdirTemp := osMkdirTemp
	defer func() { osMkdirTemp = oldMkdirTemp }()
	
	osMkdirTemp = func(dir, pattern string) (string, error) {
		tempDir, err := oldMkdirTemp(dir, pattern)
		if err == nil {
			createdDirs = append(createdDirs, tempDir)
		}
		return tempDir, err
	}

	// Override exec to fail
	oldCommandContext := execCommandContext
	defer func() { execCommandContext = oldCommandContext }()
	
	execCommandContext = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		cmd := exec.Command("false") // Always fails
		return cmd
	}

	// Run scan (should fail)
	_, err := scanner.Scan(context.Background(), project, []string{"example.com"}, nil)
	assert.Error(t, err)

	// Verify temp directories were cleaned up
	for _, dir := range createdDirs {
		_, err := os.Stat(dir)
		assert.True(t, os.IsNotExist(err), "temp directory should be removed: %s", dir)
	}
}

// osMkdirTemp is a variable to allow mocking in tests
var osMkdirTemp = os.MkdirTemp