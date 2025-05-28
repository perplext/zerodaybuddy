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

// AmassScanner implements the Scanner interface for Amass
type AmassScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewAmassScanner creates a new Amass scanner
func NewAmassScanner(config config.ToolsConfig, logger *utils.Logger) Scanner {
	return &AmassScanner{
		config: config,
		logger: logger,
	}
}

// Name returns the name of the scanner
func (s *AmassScanner) Name() string {
	return "amass"
}

// Description returns a description of the scanner
func (s *AmassScanner) Description() string {
	return "Discovers subdomains using Amass"
}

// Scan performs a subdomain discovery scan
func (s *AmassScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	domain, ok := target.(string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Amass: %T", target)
	}

	s.logger.Debug("Starting Amass scan for domain: %s", domain)

	// Ensure we have the path to Amass
	amassPath := "amass"
	if s.config.SubfinderPath != "" {
		// Hypothetical config for amass path
		amassPath = "amass"
	}

	// We'll use Amass in passive mode to avoid active fingerprinting
	// This respects the ethical guidelines of only doing passive recon
	args := []string{
		"enum",
		"-passive",     // Passive mode only
		"-d", domain,   // Target domain
		"-timeout", "10", // 10 minute timeout
	}

	// Execute the command with a timeout
	cmd := exec.CommandContext(ctx, amassPath, args...)
	output, err := cmd.Output()
	if err != nil {
		// Check if it's an ExitError which might contain stderr
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("amass failed: %v, stderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("amass failed: %v", err)
	}

	// Parse the output
	var subdomains []string
	for _, line := range strings.Split(string(output), "\n") {
		// Amass usually outputs a line for each subdomain
		subdomain := strings.TrimSpace(line)
		if subdomain != "" && strings.Contains(subdomain, domain) {
			// Extract just the subdomain part
			parts := strings.Fields(subdomain)
			if len(parts) > 0 {
				for _, part := range parts {
					if strings.HasSuffix(part, domain) {
						subdomains = append(subdomains, part)
						break
					}
				}
			}
		}
	}

	s.logger.Debug("Amass found %d subdomains for domain %s", len(subdomains), domain)

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
