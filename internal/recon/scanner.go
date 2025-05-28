package recon

import (
	"context"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// Scanner defines the interface for all scanning tools
type Scanner interface {
	// Name returns the name of the scanner
	Name() string

	// Description returns a description of the scanner
	Description() string

	// Scan performs the actual scanning operation
	// - ctx: context for timeout and cancellation
	// - project: the project being scanned (used for scope checking)
	// - target: can be a string (domain/URL) or a slice of domains/URLs depending on the scanner
	// - options: additional scanner-specific options
	// Returns interface{} which should be cast to the appropriate type by the caller
	Scan(ctx context.Context, project *models.Project, target interface{}, options map[string]interface{}) (interface{}, error)
}
