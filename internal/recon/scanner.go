package recon

import (
	"context"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// ScanOptions provides type-safe scanner configuration.
type ScanOptions struct {
	Templates   string
	Severity    string
	Wordlist    string
	DAST        bool   // Enable DAST/fuzzing mode (Nuclei)
	InputMode   string // e.g. "openapi" for Nuclei API schema import
	FuzzingType string // replace, prefix, postfix, infix
	FuzzingMode string // multiple, single
	Extra       map[string]interface{}
}

// ScannerMeta provides common metadata for all scanners.
type ScannerMeta interface {
	Name() string
	Description() string
}

// SubdomainScanner discovers subdomains for a given domain.
type SubdomainScanner interface {
	ScannerMeta
	ScanSubdomains(ctx context.Context, project *models.Project, domain string, opts ScanOptions) ([]string, error)
}

// HostProber probes hosts for live HTTP services.
type HostProber interface {
	ScannerMeta
	ProbeHosts(ctx context.Context, project *models.Project, hosts []string, opts ScanOptions) ([]*models.Host, error)
}

// PortScanner discovers open ports on targets.
type PortScanner interface {
	ScannerMeta
	ScanPorts(ctx context.Context, project *models.Project, targets []string, opts ScanOptions) ([]*models.Host, error)
}

// EndpointDiscoverer discovers endpoints (URLs/paths) from targets.
type EndpointDiscoverer interface {
	ScannerMeta
	DiscoverEndpoints(ctx context.Context, project *models.Project, urls []string, opts ScanOptions) ([]*models.Endpoint, error)
}

// VulnerabilityScanner scans targets for vulnerabilities.
type VulnerabilityScanner interface {
	ScannerMeta
	ScanVulnerabilities(ctx context.Context, project *models.Project, targets []string, opts ScanOptions) ([]*models.Finding, error)
}

// Scanner is kept for backward compatibility during transition.
// New scanners should implement one of the typed interfaces above.
type Scanner interface {
	Name() string
	Description() string
	Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error)
}
