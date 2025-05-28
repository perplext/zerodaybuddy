package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// NaabuScanner implements the Scanner interface for Naabu port scanner
type NaabuScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewNaabuScanner creates a new Naabu scanner
func NewNaabuScanner(config config.ToolsConfig, logger *utils.Logger) Scanner {
	return &NaabuScanner{
		config: config,
		logger: logger,
	}
}

// Name returns the name of the scanner
func (s *NaabuScanner) Name() string {
	return "naabu"
}

// Description returns a description of the scanner
func (s *NaabuScanner) Description() string {
	return "Fast port scanner for discovering open ports"
}

// NaabuResult represents a parsed output from Naabu
type NaabuResult struct {
	Host  string `json:"host"`
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Proto string `json:"protocol"`
}

// Scan performs port scanning on a list of hosts
func (s *NaabuScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	domains, ok := target.([]string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Naabu: %T", target)
	}

	if len(domains) == 0 {
		return []NaabuResult{}, nil
	}

	s.logger.Debug("Starting Naabu scan for %d domains", len(domains))

	// Ensure we have the path to naabu
	naabuPath := s.config.NaabuPath
	if naabuPath == "" {
		naabuPath = "naabu"
	}

	// Create a temporary file to store the domains and output
	tempDir, err := os.MkdirTemp("", "zerodaybuddy-naabu")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	domainsFile := filepath.Join(tempDir, "domains.txt")
	outputFile := filepath.Join(tempDir, "naabu_output.json")

	// Write domains to the temporary file
	if err := os.WriteFile(domainsFile, []byte(strings.Join(domains, "\n")), 0644); err != nil {
		return nil, fmt.Errorf("failed to write domains to file: %v", err)
	}

	// Determine which ports to scan based on options
	ports := "top-1000" // Default to top 1000 ports
	if options != nil {
		if portsOpt, ok := options["ports"].(string); ok && portsOpt != "" {
			ports = portsOpt
		}
	}

	// Build command arguments
	args := []string{
		"-list", domainsFile,
		"-json",
		"-o", outputFile,
		"-p", ports,
		"-rate", "1000", // Rate limiting to avoid being blocked
		"-timeout", "5000", // 5 second timeout per host
		"-silent",
	}

	// Execute the command
	cmd := exec.CommandContext(ctx, naabuPath, args...)
	if _, err := cmd.Output(); err != nil {
		// Check if it's an ExitError which might contain stderr
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("naabu failed: %v, stderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("naabu failed: %v", err)
	}

	// Read and parse the output
	outputData, err := os.ReadFile(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read naabu output: %v", err)
	}

	// Naabu outputs JSON objects one per line
	var results []NaabuResult
	for _, line := range strings.Split(string(outputData), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var result NaabuResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			s.logger.Warn("Failed to parse naabu result: %v, line: %s", err, line)
			continue
		}

		// Only include hosts that are in scope
		if project.Scope.IsInScope(models.AssetTypeDomain, result.Host) {
			results = append(results, result)
		}
	}

	s.logger.Debug("Naabu found %d open ports across %d domains", len(results), len(domains))

	return results, nil
}
