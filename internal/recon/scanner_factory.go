package recon

import (
	"fmt"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// ScannerFactory creates and provides scanner instances
type ScannerFactory struct {
	config config.Config
	logger *utils.Logger
	scanners map[string]Scanner
}

// NewScannerFactory creates a new scanner factory
func NewScannerFactory(config config.Config, logger *utils.Logger) *ScannerFactory {
	factory := &ScannerFactory{
		config:   config,
		logger:   logger,
		scanners: make(map[string]Scanner),
	}

	// Initialize all supported scanners
	factory.registerScanners()
	
	return factory
}

// registerScanners initializes and registers all supported scanners
func (f *ScannerFactory) registerScanners() {
	// Register subdomain discovery scanners
	f.scanners["subfinder"] = NewSubfinderScanner(f.config.Tools, f.logger)
	f.scanners["amass"] = NewAmassScanner(f.config.Tools, f.logger)
	
	// Register HTTP probing scanners
	f.scanners["httpx"] = NewHTTPXScanner(f.config.Tools, f.logger)
	
	// Register port scanning tools
	f.scanners["naabu"] = NewNaabuScanner(f.config.Tools, f.logger)
	
	// Register content discovery tools
	f.scanners["ffuf"] = NewFFUFScanner(f.config.Tools, f.logger)
	
	// Register crawling tools
	f.scanners["katana"] = NewKatanaScanner(f.config.Tools, f.logger)
	f.scanners["wayback"] = NewWaybackScanner(f.config.Tools, f.logger)
	
	// Register vulnerability scanning tools
	f.scanners["nuclei"] = NewNucleiScanner(f.config.Tools, f.logger)
}

// GetScanner returns a scanner by name
func (f *ScannerFactory) GetScanner(name string) (Scanner, error) {
	scanner, exists := f.scanners[name]
	if !exists {
		return nil, fmt.Errorf("scanner '%s' not found", name)
	}
	return scanner, nil
}

// ListScanners returns a list of all available scanners
func (f *ScannerFactory) ListScanners() []Scanner {
	scanners := make([]Scanner, 0, len(f.scanners))
	for _, scanner := range f.scanners {
		scanners = append(scanners, scanner)
	}
	return scanners
}

// GetScannerByType returns all scanners of a specific type
func (f *ScannerFactory) GetScannersByType(scannerType string) []Scanner {
	var result []Scanner
	
	switch scannerType {
	case "subdomain":
		if s, ok := f.scanners["subfinder"]; ok {
			result = append(result, s)
		}
		if s, ok := f.scanners["amass"]; ok {
			result = append(result, s)
		}
	case "http":
		if s, ok := f.scanners["httpx"]; ok {
			result = append(result, s)
		}
	case "port":
		if s, ok := f.scanners["naabu"]; ok {
			result = append(result, s)
		}
	case "content":
		if s, ok := f.scanners["ffuf"]; ok {
			result = append(result, s)
		}
	case "vulnerability":
		if s, ok := f.scanners["nuclei"]; ok {
			result = append(result, s)
		}
	}
	
	return result
}
