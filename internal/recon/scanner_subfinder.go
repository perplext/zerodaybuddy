package recon

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// SubfinderScanner implements the Scanner interface for Subfinder
type SubfinderScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewSubfinderScanner creates a new Subfinder scanner
func NewSubfinderScanner(config config.ToolsConfig, logger *utils.Logger) Scanner {
	return &SubfinderScanner{
		config: config,
		logger: logger,
	}
}

// Name returns the name of the scanner
func (s *SubfinderScanner) Name() string {
	return "subfinder"
}

// Description returns a description of the scanner
func (s *SubfinderScanner) Description() string {
	return "Discovers subdomains using Subfinder"
}

// Scan performs a subdomain discovery scan
func (s *SubfinderScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	domain, ok := target.(string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Subfinder: %T", target)
	}

	s.logger.Debug("Starting Subfinder scan for domain: %s", domain)

	// Ensure we have the path to Subfinder
	subfinderPath := s.config.SubfinderPath
	if subfinderPath == "" {
		subfinderPath = "subfinder"
	}

	// Build command arguments
	args := []string{
		"-d", domain,
		"-silent",       // Only print subdomains
		"-timeout", "30", // Set a reasonable timeout
	}

	// Add -all flag to get subdomains from all sources
	args = append(args, "-all")

	// Add rate limiting to avoid triggering WAFs or being blocked
	rateLimit := 150 // Default rate limit
	if options != nil {
		if val, ok := options["rate_limit"].(int); ok && val > 0 {
			rateLimit = val
		}
	}
	args = append(args, "-rate-limit", fmt.Sprintf("%d", rateLimit))

	// Execute the command
	cmd := exec.CommandContext(ctx, subfinderPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// Check if it's an ExitError which might contain stderr
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("subfinder failed: %v, stderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("subfinder failed: %v", err)
	}

	// Parse the output
	var subdomains []string
	for _, line := range strings.Split(string(output), "\n") {
		subdomain := strings.TrimSpace(line)
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}

	s.logger.Debug("Subfinder found %d subdomains for domain %s", len(subdomains), domain)

	// Filter out-of-scope subdomains
	var inScopeSubdomains []string
	for _, subdomain := range subdomains {
		if project.Scope.IsInScope(models.AssetTypeDomain, subdomain) {
			inScopeSubdomains = append(inScopeSubdomains, subdomain)
		}
	}

	s.logger.Debug("After scope filtering, %d subdomains are in scope", len(inScopeSubdomains))

	return inScopeSubdomains, nil
}
