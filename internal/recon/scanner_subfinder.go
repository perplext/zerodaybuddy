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
func NewSubfinderScanner(config config.ToolsConfig, logger *utils.Logger) *SubfinderScanner {
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

// ScanSubdomains implements SubdomainScanner.
func (s *SubfinderScanner) ScanSubdomains(ctx context.Context, project *models.Project, domain string, opts ScanOptions) ([]string, error) {
	s.logger.Debug("Starting Subfinder scan for domain: %s", domain)

	subfinderPath := s.config.SubfinderPath
	if subfinderPath == "" {
		subfinderPath = "subfinder"
	}

	args := []string{
		"-d", domain,
		"-silent",
		"-timeout", "30",
		"-all",
	}

	rateLimit := 150
	if v, ok := opts.Extra["rate_limit"].(int); ok && v > 0 {
		rateLimit = v
	}
	args = append(args, "-rate-limit", fmt.Sprintf("%d", rateLimit))

	cmd := exec.CommandContext(ctx, subfinderPath, args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("subfinder failed: %v, stderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("subfinder failed: %v", err)
	}

	var subdomains []string
	for _, line := range strings.Split(string(output), "\n") {
		subdomain := strings.TrimSpace(line)
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}

	s.logger.Debug("Subfinder found %d subdomains for domain %s", len(subdomains), domain)

	var inScopeSubdomains []string
	for _, subdomain := range subdomains {
		if project.Scope.IsInScope(models.AssetTypeDomain, subdomain) {
			inScopeSubdomains = append(inScopeSubdomains, subdomain)
		}
	}

	s.logger.Debug("After scope filtering, %d subdomains are in scope", len(inScopeSubdomains))
	return inScopeSubdomains, nil
}

// Scan implements the legacy Scanner interface by delegating to ScanSubdomains.
func (s *SubfinderScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	domain, ok := target.(string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Subfinder: %T", target)
	}
	return s.ScanSubdomains(ctx, project, domain, ScanOptions{Extra: options})
}
