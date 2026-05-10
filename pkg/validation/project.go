package validation

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/perplext/zerodaybuddy/pkg/models"
)

// ProjectStore defines the interface for project validation
type ProjectStore interface {
	GetProjectByName(ctx context.Context, name string) (*models.Project, error)
}

// ProjectExists validates that a project exists in the database
func ProjectExists(ctx context.Context, store ProjectStore, projectName string) error {
	if err := ProjectName(projectName); err != nil {
		return err
	}

	if _, err := store.GetProjectByName(ctx, projectName); err != nil {
		return fmt.Errorf("project '%s' not found", projectName)
	}

	return nil
}

// ProjectScope validates that a target is within the project's scope.
// For URL targets, the target's host is extracted and matched against in-scope
// Domain and URL assets using dot-anchored matching to prevent boundary-bypass
// attacks (e.g., "evil-example.com" must not match in-scope "example.com").
func ProjectScope(ctx context.Context, store ProjectStore, projectName string, target string) error {
	project, err := store.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("project '%s' not found", projectName)
	}

	if isURL(target) {
		targetHost := extractHost(target)
		if targetHost == "" {
			return fmt.Errorf("target '%s' is not in project scope", target)
		}
		for _, asset := range project.Scope.InScope {
			switch asset.Type {
			case models.AssetTypeDomain:
				if matchesDomain(targetHost, asset.Value) {
					return nil
				}
			case models.AssetTypeURL:
				assetHost := extractHost(asset.Value)
				if assetHost != "" && matchesDomain(targetHost, assetHost) {
					return nil
				}
			}
		}
		return fmt.Errorf("target '%s' is not in project scope", target)
	}

	for _, asset := range project.Scope.InScope {
		if asset.Value == target {
			return nil
		}
	}

	return fmt.Errorf("target '%s' is not in project scope", target)
}

// matchesDomain reports whether targetHost matches scopeDomain using dot-anchored
// boundary-safe rules. It accepts exact matches, subdomain matches, and wildcard
// patterns of the form "*.example.com" (which match both "example.com" and any
// subdomain of it). Comparisons are case-insensitive and trailing dots are stripped.
//
// The dot anchoring is the security-critical detail: matchesDomain("evil-example.com",
// "example.com") returns false because the suffix check requires ".example.com",
// not "example.com".
func matchesDomain(targetHost, scopeDomain string) bool {
	if targetHost == "" || scopeDomain == "" {
		return false
	}

	target := strings.ToLower(strings.TrimSuffix(targetHost, "."))

	if strings.HasPrefix(scopeDomain, "*.") {
		parent := strings.ToLower(strings.TrimSuffix(scopeDomain[2:], "."))
		if parent == "" {
			return false
		}
		if target == parent {
			return true
		}
		return strings.HasSuffix(target, "."+parent)
	}

	scope := strings.ToLower(strings.TrimSuffix(scopeDomain, "."))
	if target == scope {
		return true
	}
	return strings.HasSuffix(target, "."+scope)
}

// extractHost returns the hostname (port-stripped) from a URL string. Returns
// the empty string when the input cannot be parsed as a URL with a host.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// isURL reports whether s starts with an http:// or https:// scheme.
func isURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
