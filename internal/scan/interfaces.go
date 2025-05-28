package scan

import (
	"github.com/perplext/zerodaybuddy/internal/recon"
)

// ScannerFactory is an interface for scanner factory implementations
type ScannerFactory interface {
	GetScanner(name string) (recon.Scanner, error)
}