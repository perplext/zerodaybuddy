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

// AmassScanner implements SubdomainScanner using Amass.
type AmassScanner struct {
	config config.ToolsConfig
	logger *utils.Logger
}

// NewAmassScanner creates a new Amass scanner.
func NewAmassScanner(config config.ToolsConfig, logger *utils.Logger) *AmassScanner {
	return &AmassScanner{
		config: config,
		logger: logger,
	}
}

func (s *AmassScanner) Name() string        { return "amass" }
func (s *AmassScanner) Description() string { return "Discovers subdomains using Amass" }

// ScanSubdomains implements SubdomainScanner.
func (s *AmassScanner) ScanSubdomains(ctx context.Context, project *models.Project, domain string, opts ScanOptions) ([]string, error) {
	s.logger.Debug("Starting Amass scan for domain: %s", domain)

	args := []string{
		"enum",
		"-passive",
		"-d", domain,
		"-timeout", "10",
	}

	amassPath := s.config.AmassPath
	if amassPath == "" {
		amassPath = "amass"
	}

	cmd := exec.CommandContext(ctx, amassPath, args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("amass failed: %v, stderr: %s", err, exitErr.Stderr)
		}
		return nil, fmt.Errorf("amass failed: %v", err)
	}

	var subdomains []string
	for _, line := range strings.Split(string(output), "\n") {
		subdomain := strings.TrimSpace(line)
		if subdomain != "" && strings.Contains(subdomain, domain) {
			parts := strings.Fields(subdomain)
			for _, part := range parts {
				if part == domain || strings.HasSuffix(part, "."+domain) {
					subdomains = append(subdomains, part)
					break
				}
			}
		}
	}

	s.logger.Debug("Amass found %d subdomains for domain %s", len(subdomains), domain)

	var inScopeSubdomains []string
	for _, subdomain := range subdomains {
		if project.Scope.IsInScope(models.AssetTypeDomain, subdomain) {
			inScopeSubdomains = append(inScopeSubdomains, subdomain)
		}
	}

	s.logger.Debug("After scope filtering, %d subdomains are in scope", len(inScopeSubdomains))
	return inScopeSubdomains, nil
}

// Scan implements the legacy Scanner interface.
func (s *AmassScanner) Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error) {
	domain, ok := target.(string)
	if !ok {
		return nil, fmt.Errorf("invalid target type for Amass: %T", target)
	}
	return s.ScanSubdomains(ctx, project, domain, ScanOptions{Extra: options})
}
