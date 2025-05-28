package platform

import (
	"context"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

// TestPlatformInterface ensures both HackerOne and Bugcrowd implement the Platform interface
func TestPlatformInterface(t *testing.T) {
	logger := utils.NewLogger("", false)

	// Test that HackerOne implements Platform
	h1Config := config.HackerOneConfig{
		APIUrl:   "https://api.hackerone.com",
		Username: "test",
		APIKey:   "test",
	}
	var h1Platform Platform = NewHackerOne(h1Config, logger)
	assert.NotNil(t, h1Platform)
	assert.Equal(t, "hackerone", h1Platform.GetName())

	// Test that Bugcrowd implements Platform
	bcConfig := config.BugcrowdConfig{
		APIUrl:      "https://bugcrowd.com",
		CookieValue: "test",
	}
	var bcPlatform Platform = NewBugcrowd(bcConfig, logger)
	assert.NotNil(t, bcPlatform)
	assert.Equal(t, "bugcrowd", bcPlatform.GetName())

	// Verify all methods exist (compile-time check)
	ctx := context.Background()
	platforms := []Platform{h1Platform, bcPlatform}

	for _, p := range platforms {
		// These calls will fail at runtime due to lack of valid credentials,
		// but they verify the methods exist and have correct signatures
		_, _ = p.ListPrograms(ctx)
		_, _ = p.GetProgram(ctx, "test")
		_, _ = p.FetchScope(ctx, "test")
		_ = p.GetName()
	}
}

// TestAssetTypeConstants verifies all asset type constants are valid
func TestAssetTypeConstants(t *testing.T) {
	// Ensure all asset types are distinct
	assetTypes := []models.AssetType{
		models.AssetTypeDomain,
		models.AssetTypeURL,
		models.AssetTypeIP,
		models.AssetTypeMobile,
		models.AssetTypeBinary,
		models.AssetTypeOther,
	}

	seen := make(map[models.AssetType]bool)
	for _, at := range assetTypes {
		assert.False(t, seen[at], "Duplicate asset type: %s", at)
		seen[at] = true
	}

	// Verify string values
	assert.Equal(t, "domain", string(models.AssetTypeDomain))
	assert.Equal(t, "url", string(models.AssetTypeURL))
	assert.Equal(t, "ip", string(models.AssetTypeIP))
	assert.Equal(t, "mobile", string(models.AssetTypeMobile))
	assert.Equal(t, "binary", string(models.AssetTypeBinary))
	assert.Equal(t, "other", string(models.AssetTypeOther))
}

// TestProgramStructure verifies the Program struct has all required fields
func TestProgramStructure(t *testing.T) {
	program := models.Program{
		ID:          "123",
		Name:        "Test Program",
		Handle:      "test-program",
		Description: "Description",
		URL:         "https://example.com",
		Platform:    "hackerone",
		Policy:      "Policy text",
		Scope: models.Scope{
			InScope: []models.Asset{
				{
					Type:  models.AssetTypeDomain,
					Value: "*.example.com",
				},
			},
			OutOfScope: []models.Asset{
				{
					Type:  models.AssetTypeIP,
					Value: "192.168.1.0/24",
				},
			},
		},
	}

	// Verify all fields are accessible
	assert.Equal(t, "123", program.ID)
	assert.Equal(t, "Test Program", program.Name)
	assert.Equal(t, "test-program", program.Handle)
	assert.Equal(t, "Description", program.Description)
	assert.Equal(t, "https://example.com", program.URL)
	assert.Equal(t, "hackerone", program.Platform)
	assert.Equal(t, "Policy text", program.Policy)
	assert.Len(t, program.Scope.InScope, 1)
	assert.Len(t, program.Scope.OutOfScope, 1)
}

// TestScopeStructure verifies the Scope struct and Asset struct
func TestScopeStructure(t *testing.T) {
	asset := models.Asset{
		Type:         models.AssetTypeDomain,
		Value:        "*.example.com",
		Description:  "All subdomains",
		Instructions: "Test all subdomains",
		Attributes: map[string]interface{}{
			"critical": true,
			"priority": 1,
		},
	}

	assert.Equal(t, models.AssetTypeDomain, asset.Type)
	assert.Equal(t, "*.example.com", asset.Value)
	assert.Equal(t, "All subdomains", asset.Description)
	assert.Equal(t, "Test all subdomains", asset.Instructions)
	assert.Equal(t, true, asset.Attributes["critical"])
	assert.Equal(t, 1, asset.Attributes["priority"])

	scope := models.Scope{
		InScope:    []models.Asset{asset},
		OutOfScope: []models.Asset{},
	}

	assert.Len(t, scope.InScope, 1)
	assert.Empty(t, scope.OutOfScope)
}

// mockPlatform is a simple mock implementation for testing
type mockPlatform struct {
	name          string
	programs      []models.Program
	programsError error
	program       *models.Program
	programError  error
	scope         *models.Scope
	scopeError    error
}

func (m *mockPlatform) ListPrograms(ctx context.Context) ([]models.Program, error) {
	if m.programsError != nil {
		return nil, m.programsError
	}
	return m.programs, nil
}

func (m *mockPlatform) GetProgram(ctx context.Context, handle string) (*models.Program, error) {
	if m.programError != nil {
		return nil, m.programError
	}
	return m.program, nil
}

func (m *mockPlatform) FetchScope(ctx context.Context, handle string) (*models.Scope, error) {
	if m.scopeError != nil {
		return nil, m.scopeError
	}
	return m.scope, nil
}

func (m *mockPlatform) GetName() string {
	return m.name
}

// TestMockPlatform verifies our mock implementation works correctly
func TestMockPlatform(t *testing.T) {
	mock := &mockPlatform{
		name: "mock",
		programs: []models.Program{
			{ID: "1", Name: "Program 1"},
			{ID: "2", Name: "Program 2"},
		},
		program: &models.Program{
			ID:   "1",
			Name: "Program 1",
		},
		scope: &models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
			},
		},
	}

	// Verify it implements Platform interface
	var p Platform = mock
	assert.Equal(t, "mock", p.GetName())

	ctx := context.Background()

	// Test ListPrograms
	programs, err := p.ListPrograms(ctx)
	assert.NoError(t, err)
	assert.Len(t, programs, 2)

	// Test GetProgram
	program, err := p.GetProgram(ctx, "test")
	assert.NoError(t, err)
	assert.Equal(t, "1", program.ID)

	// Test FetchScope
	scope, err := p.FetchScope(ctx, "test")
	assert.NoError(t, err)
	assert.Len(t, scope.InScope, 1)
}