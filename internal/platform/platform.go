package platform

import (
	"context"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// Platform defines the interface for bug bounty platforms
type Platform interface {
	// ListPrograms lists all available bug bounty programs
	ListPrograms(ctx context.Context) ([]models.Program, error)
	
	// GetProgram retrieves a specific bug bounty program
	GetProgram(ctx context.Context, handle string) (*models.Program, error)
	
	// FetchScope fetches the scope for a bug bounty program
	FetchScope(ctx context.Context, handle string) (*models.Scope, error)
	
	// GetName returns the name of the platform
	GetName() string
}
