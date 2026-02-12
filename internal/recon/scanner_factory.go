package recon

import (
	"fmt"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// ScannerRegistry creates, registers, and provides scanner instances.
// It auto-categorizes scanners by interface type assertions.
type ScannerRegistry struct {
	config config.Config
	logger *utils.Logger

	all                 map[string]Scanner
	subdomainScanners   []SubdomainScanner
	hostProbers         []HostProber
	portScanners        []PortScanner
	endpointDiscoverers []EndpointDiscoverer
	vulnScanners        []VulnerabilityScanner
}

// ScannerFactory is an alias for backward compatibility.
type ScannerFactory = ScannerRegistry

// NewScannerRegistry creates a new scanner registry and registers all known scanners.
func NewScannerRegistry(cfg config.Config, logger *utils.Logger) *ScannerRegistry {
	r := &ScannerRegistry{
		config: cfg,
		logger: logger,
		all:    make(map[string]Scanner),
	}
	r.registerDefaults()
	return r
}

// NewScannerFactory is a backward-compatible alias for NewScannerRegistry.
func NewScannerFactory(cfg config.Config, logger *utils.Logger) *ScannerRegistry {
	return NewScannerRegistry(cfg, logger)
}

// Register adds a scanner and auto-categorizes it by the typed interfaces it implements.
func (r *ScannerRegistry) Register(scanner Scanner) {
	r.all[scanner.Name()] = scanner

	if s, ok := scanner.(SubdomainScanner); ok {
		r.subdomainScanners = append(r.subdomainScanners, s)
	}
	if s, ok := scanner.(HostProber); ok {
		r.hostProbers = append(r.hostProbers, s)
	}
	if s, ok := scanner.(PortScanner); ok {
		r.portScanners = append(r.portScanners, s)
	}
	if s, ok := scanner.(EndpointDiscoverer); ok {
		r.endpointDiscoverers = append(r.endpointDiscoverers, s)
	}
	if s, ok := scanner.(VulnerabilityScanner); ok {
		r.vulnScanners = append(r.vulnScanners, s)
	}
}

// registerDefaults initializes and registers all built-in scanners.
func (r *ScannerRegistry) registerDefaults() {
	r.Register(NewSubfinderScanner(r.config.Tools, r.logger))
	r.Register(NewAmassScanner(r.config.Tools, r.logger))
	r.Register(NewHTTPXScanner(r.config.Tools, r.logger))
	r.Register(NewNaabuScanner(r.config.Tools, r.logger))
	r.Register(NewFFUFScanner(r.config.Tools, r.logger))
	r.Register(NewKatanaScanner(r.config.Tools, r.logger))
	r.Register(NewWaybackScanner(r.config.Tools, r.logger))
	r.Register(NewNucleiScanner(r.config.Tools, r.logger))
	r.Register(NewTrivyScanner(r.config.Tools, r.logger))
	r.Register(NewGitleaksScanner(r.config.Tools, r.logger))
}

// GetScanner returns a scanner by name.
func (r *ScannerRegistry) GetScanner(name string) (Scanner, error) {
	scanner, exists := r.all[name]
	if !exists {
		return nil, fmt.Errorf("scanner '%s' not found", name)
	}
	return scanner, nil
}

// ListScanners returns all registered scanners.
func (r *ScannerRegistry) ListScanners() []Scanner {
	scanners := make([]Scanner, 0, len(r.all))
	for _, scanner := range r.all {
		scanners = append(scanners, scanner)
	}
	return scanners
}

// SubdomainScanners returns all scanners that implement SubdomainScanner.
func (r *ScannerRegistry) SubdomainScanners() []SubdomainScanner {
	return r.subdomainScanners
}

// HostProbers returns all scanners that implement HostProber.
func (r *ScannerRegistry) HostProbers() []HostProber {
	return r.hostProbers
}

// PortScanners returns all scanners that implement PortScanner.
func (r *ScannerRegistry) PortScanners() []PortScanner {
	return r.portScanners
}

// EndpointDiscoverers returns all scanners that implement EndpointDiscoverer.
func (r *ScannerRegistry) EndpointDiscoverers() []EndpointDiscoverer {
	return r.endpointDiscoverers
}

// VulnerabilityScanners returns all scanners that implement VulnerabilityScanner.
func (r *ScannerRegistry) VulnerabilityScanners() []VulnerabilityScanner {
	return r.vulnScanners
}

// GetScannersByType returns scanners matching a type string.
// Kept for backward compatibility; prefer the typed accessor methods.
func (r *ScannerRegistry) GetScannersByType(scannerType string) []Scanner {
	var result []Scanner

	switch scannerType {
	case "subdomain":
		for _, s := range r.subdomainScanners {
			result = append(result, s.(Scanner))
		}
	case "http":
		for _, s := range r.hostProbers {
			result = append(result, s.(Scanner))
		}
	case "port":
		for _, s := range r.portScanners {
			result = append(result, s.(Scanner))
		}
	case "content":
		for _, s := range r.endpointDiscoverers {
			result = append(result, s.(Scanner))
		}
	case "vulnerability":
		for _, s := range r.vulnScanners {
			result = append(result, s.(Scanner))
		}
	}

	return result
}
