package validation

import (
	"context"
	"fmt"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/stretchr/testify/assert"
)

// mockProjectStore implements ProjectStore for testing
type mockProjectStore struct {
	project *models.Project
	err     error
}

func (m *mockProjectStore) GetProjectByName(ctx context.Context, name string) (*models.Project, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.project, nil
}

func TestProjectExists(t *testing.T) {
	tests := []struct {
		name        string
		projectName string
		store       *mockProjectStore
		wantErr     bool
	}{
		{
			"project exists",
			"test-project",
			&mockProjectStore{project: &models.Project{Name: "test-project"}},
			false,
		},
		{
			"project not found",
			"nonexistent",
			&mockProjectStore{err: fmt.Errorf("not found")},
			true,
		},
		{
			"invalid project name",
			"",
			&mockProjectStore{},
			true,
		},
		{
			"invalid project name special chars",
			"test project!",
			&mockProjectStore{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProjectExists(context.Background(), tt.store, tt.projectName)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMatchesDomain(t *testing.T) {
	tests := []struct {
		name        string
		targetHost  string
		scopeDomain string
		want        bool
	}{
		// Exact match
		{"exact match", "example.com", "example.com", true},
		{"case insensitive match", "Example.COM", "example.com", true},

		// Subdomain matching
		{"subdomain match", "sub.example.com", "example.com", true},
		{"deep subdomain match", "a.b.c.example.com", "example.com", true},

		// Domain boundary — the critical security fix
		{"boundary bypass blocked", "evil-example.com", "example.com", false},
		{"boundary bypass prefix blocked", "notexample.com", "example.com", false},
		{"boundary bypass suffix blocked", "example.com.evil.com", "example.com", false},

		// Wildcard matching
		{"wildcard subdomain match", "sub.example.com", "*.example.com", true},
		{"wildcard deep subdomain match", "a.b.example.com", "*.example.com", true},
		{"wildcard base domain match", "example.com", "*.example.com", true},
		{"wildcard blocks unrelated", "evil.com", "*.example.com", false},
		{"wildcard boundary safe", "evil-example.com", "*.example.com", false},

		// No match
		{"completely different domain", "other.com", "example.com", false},
		{"empty target", "", "example.com", false},
		{"empty scope", "example.com", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesDomain(tt.targetHost, tt.scopeDomain)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProjectScope_DomainBoundary(t *testing.T) {
	project := &models.Project{
		Name: "test-project",
		Scope: models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
				{Type: models.AssetTypeURL, Value: "https://api.target.io"},
			},
		},
	}
	store := &mockProjectStore{project: project}

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		// Should match
		{"exact domain in URL", "https://example.com/path", false},
		{"subdomain in URL", "https://sub.example.com/api", false},
		{"scope URL exact match", "https://api.target.io/v1", false},

		// Should NOT match (bypass attempts)
		{"boundary bypass", "https://evil-example.com/path", true},
		{"prefix bypass", "https://notexample.com", true},
		{"unrelated domain", "https://other.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProjectScope(context.Background(), store, "test-project", tt.target)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProjectScope_NonURL(t *testing.T) {
	project := &models.Project{
		Name: "test-project",
		Scope: models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
			},
		},
	}
	store := &mockProjectStore{project: project}

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"exact match", "example.com", false},
		{"no match", "other.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ProjectScope(context.Background(), store, "test-project", tt.target)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractHost(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"simple URL", "https://example.com", "example.com"},
		{"URL with port", "https://example.com:8443", "example.com"},
		{"URL with path", "https://example.com/api/v1", "example.com"},
		{"URL with subdomain", "https://sub.example.com", "sub.example.com"},
		{"invalid URL", "not a url", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHost(tt.url)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"https URL", "https://example.com", true},
		{"http URL", "http://example.com", true},
		{"not a URL", "example.com", false},
		{"ftp URL", "ftp://example.com", false},
		{"short string", "http", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isURL(tt.s))
		})
	}
}
