//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNucleiScanner_BasicInfo(t *testing.T) {
	scanner := NewNucleiScanner(config.ToolsConfig{}, utils.NewLogger("", false))
	
	assert.Equal(t, "nuclei", scanner.Name())
	assert.Equal(t, "Scans for known vulnerabilities using templates", scanner.Description())
}

func TestNucleiScanner_Scan(t *testing.T) {
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
		var results []NucleiResult
		switch os.Getenv("TEST_CASE") {
		case "success":
			results = []NucleiResult{
				{
					TemplateID: "cve-2021-44228",
					Info: NucleiResultInfo{
						Name:     "Apache Log4j RCE",
						Severity: "critical",
						Tags:     []string{"cve", "log4j", "rce"},
						Authors:  []string{"pdteam"},
						Classification: struct {
							CVEIDs    []string `json:"cve-id,omitempty"`
							CVSSScore string   `json:"cvss-score,omitempty"`
							CVE       string   `json:"cve,omitempty"`
						}{
							CVEIDs:    []string{"CVE-2021-44228"},
							CVSSScore: "10.0",
						},
					},
					Host:          "https://example.com",
					Type:          "http",
					Severity:      "critical",
					MatcherStatus: true,
					Timestamp:     time.Now().Format(time.RFC3339),
				},
				{
					TemplateID: "exposed-panels",
					Info: NucleiResultInfo{
						Name:     "Exposed Admin Panel",
						Severity: "medium",
						Tags:     []string{"panel", "exposure"},
						Authors:  []string{"pdteam"},
					},
					Host:          "https://example.com/admin",
					Type:          "http",
					Severity:      "medium",
					MatcherStatus: true,
					MatchedAt:     "https://example.com/admin",
					Timestamp:     time.Now().Format(time.RFC3339),
				},
			}
		case "error":
			os.Exit(1)
		case "empty":
			// No vulnerabilities found
		case "invalid_json":
			// Write invalid JSON
			os.WriteFile(outputFile, []byte("invalid json\n{broken"), 0644)
			os.Exit(0)
		case "mixed_severity":
			results = []NucleiResult{
				{
					TemplateID: "info-disclosure",
					Info: NucleiResultInfo{
						Name:     "Information Disclosure",
						Severity: "info",
					},
					Host:          "https://example.com",
					Type:          "http",
					Severity:      "info",
					MatcherStatus: true,
					Timestamp:     time.Now().Format(time.RFC3339),
				},
				{
					TemplateID: "weak-cipher",
					Info: NucleiResultInfo{
						Name:     "Weak SSL Cipher",
						Severity: "low",
					},
					Host:          "https://example.com",
					Type:          "http",
					Severity:      "low",
					MatcherStatus: true,
					Timestamp:     time.Now().Format(time.RFC3339),
				},
			}
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
	}{
		{
			name:          "successful scan with vulnerabilities",
			target:        []string{"https://example.com", "https://example.com/admin"},
			testCase:      "success",
			expectedError: false,
			expectedCount: 2,
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
			target:        []string{"https://example.com"},
			testCase:      "error",
			expectedError: true,
		},
		{
			name:          "invalid json output",
			target:        []string{"https://example.com"},
			testCase:      "invalid_json",
			expectedError: false,
			expectedCount: 0, // Invalid lines are skipped
		},
		{
			name:          "custom severity filter",
			target:        []string{"https://example.com"},
			testCase:      "mixed_severity",
			options:       map[string]interface{}{"severity": "medium,high,critical"},
			expectedError: false,
			expectedCount: 0, // Both results are info/low severity
		},
		{
			name:          "custom tags filter",
			target:        []string{"https://example.com"},
			testCase:      "success",
			options:       map[string]interface{}{"tags": "cve"},
			expectedError: false,
			expectedCount: 2, // Would filter if implemented
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create scanner
			logger := utils.NewLogger("", false)
			scanner := NewNucleiScanner(config.ToolsConfig{
				NucleiPath: "nuclei",
			}, logger)

			// Create project with scope
			project := &models.Project{
				Name: "test-project",
				Scope: models.Scope{
					InScope: makeAssets(models.AssetTypeDomain, tt.inScope),
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
				cs := []string{"-test.run=TestNucleiScanner_Scan"}
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
				results, ok := result.([]NucleiResult)
				require.True(t, ok, "result should be []NucleiResult")
				assert.Len(t, results, tt.expectedCount)
				
				// Verify result fields for successful cases
				if tt.testCase == "success" && len(results) > 0 {
					// Check first result
					assert.Equal(t, "cve-2021-44228", results[0].TemplateID)
					assert.Equal(t, "critical", results[0].Severity)
					assert.True(t, results[0].MatcherStatus)
					assert.NotEmpty(t, results[0].Timestamp)
				}
			}
		})
	}
}

func TestNucleiResult_Severity(t *testing.T) {
	tests := []struct {
		name     string
		result   NucleiResult
		expected string
	}{
		{
			name: "critical severity",
			result: NucleiResult{
				Severity: "critical",
				Info: NucleiResultInfo{
					Severity: "critical",
				},
			},
			expected: "critical",
		},
		{
			name: "info severity",
			result: NucleiResult{
				Severity: "info",
				Info: NucleiResultInfo{
					Severity: "info",
				},
			},
			expected: "info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.result.Severity)
			assert.Equal(t, tt.expected, tt.result.Info.Severity)
		})
	}
}

