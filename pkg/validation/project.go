package validation

import (
	"context"
	"fmt"
	"strings"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// ProjectStore defines the interface for project validation
type ProjectStore interface {
	GetProjectByName(ctx context.Context, name string) (*models.Project, error)
}

// ProjectExists validates that a project exists in the database
func ProjectExists(ctx context.Context, store ProjectStore, projectName string) error {
	// First validate the project name format
	if err := ProjectName(projectName); err != nil {
		return err
	}
	
	// Check if project exists
	_, err := store.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project '%s' not found", projectName)
	}
	
	return nil
}

// ProjectScope validates that a target is within the project's scope
func ProjectScope(ctx context.Context, store ProjectStore, projectName string, target string) error {
	// Get the project
	project, err := store.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project '%s' not found", projectName)
	}
	
	// Check if target is in scope
	// For URLs, extract the domain
	if isURL(target) {
		// Parse URL and check domain against scope
		// This is a simplified check - in production, you'd want more sophisticated scope checking
		for _, asset := range project.Scope.InScope {
			if asset.Type == models.AssetTypeDomain || asset.Type == models.AssetTypeURL {
				// Simple contains check - in production, use proper domain matching
				if strings.Contains(target, asset.Value) {
					return nil
				}
			}
		}
		return fmt.Errorf("target '%s' is not in project scope", target)
	}
	
	// For non-URLs, check direct match
	for _, asset := range project.Scope.InScope {
		if asset.Value == target {
			return nil
		}
	}
	
	return fmt.Errorf("target '%s' is not in project scope", target)
}

// Helper function to check if string is URL
func isURL(s string) bool {
	return len(s) > 7 && (s[:7] == "http://" || s[:8] == "https://")
}

