package storage

import (
	"context"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBulkCreateHosts_Success(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create a project first
	project := &models.Project{
		Name:     "Bulk Test Project",
		Handle:   "bulk-test",
		Platform: "hackerone",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Bulk create hosts
	sqliteStore := store.(*SQLiteStore)
	hosts := []*models.Host{
		{
			ProjectID:    project.ID,
			Type:         models.AssetTypeDomain,
			Value:        "host1.example.com",
			IP:           "10.0.0.1",
			Status:       "active",
			Technologies: []string{"nginx"},
			Ports:        []int{80, 443},
			Headers:      map[string]string{"Server": "nginx"},
			FoundBy:      "subfinder",
		},
		{
			ProjectID: project.ID,
			Type:      models.AssetTypeDomain,
			Value:     "host2.example.com",
			IP:        "10.0.0.2",
			Status:    "active",
			FoundBy:   "amass",
		},
		{
			ProjectID: project.ID,
			Type:      models.AssetTypeIP,
			Value:     "10.0.0.3",
			IP:        "10.0.0.3",
			Status:    "active",
			FoundBy:   "naabu",
		},
	}

	err = sqliteStore.BulkCreateHosts(ctx, hosts)
	require.NoError(t, err)

	// Verify all were created with IDs
	for _, h := range hosts {
		assert.NotEmpty(t, h.ID, "ID should be auto-generated")
		assert.False(t, h.CreatedAt.IsZero(), "CreatedAt should be set")
	}

	// Verify via listing
	listed, err := store.ListHosts(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 3)
}

func TestBulkCreateHosts_Empty(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	err := sqliteStore.BulkCreateHosts(context.Background(), []*models.Host{})
	assert.NoError(t, err, "empty slice should be a no-op")
}

func TestBulkCreateHosts_PreserveExistingID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	project := &models.Project{
		Name: "ID Test", Handle: "id-test", Platform: "hackerone",
		Status: models.ProjectStatusActive, Scope: models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	sqliteStore := store.(*SQLiteStore)
	customID := "custom-host-id-123"
	hosts := []*models.Host{
		{
			ID:        customID,
			ProjectID: project.ID,
			Type:      models.AssetTypeDomain,
			Value:     "custom.example.com",
			Status:    "active",
			FoundBy:   "manual",
		},
	}

	err = sqliteStore.BulkCreateHosts(ctx, hosts)
	require.NoError(t, err)
	assert.Equal(t, customID, hosts[0].ID, "pre-set ID should be preserved")

	// Verify the host can be retrieved with the custom ID
	retrieved, err := store.GetHost(ctx, customID)
	require.NoError(t, err)
	assert.Equal(t, "custom.example.com", retrieved.Value)
}

func TestBulkCreateEndpoints_Success(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	project := &models.Project{
		Name: "EP Bulk Test", Handle: "ep-bulk", Platform: "hackerone",
		Status: models.ProjectStatusActive, Scope: models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	host := &models.Host{
		ProjectID: project.ID, Type: models.AssetTypeDomain,
		Value: "api.example.com", Status: "active", FoundBy: "subfinder",
	}
	err = store.CreateHost(ctx, host)
	require.NoError(t, err)

	sqliteStore := store.(*SQLiteStore)
	endpoints := []*models.Endpoint{
		{
			ProjectID:   project.ID,
			HostID:      host.ID,
			URL:         "https://api.example.com/v1/users",
			Method:      "GET",
			Status:      200,
			ContentType: "application/json",
			Parameters: []models.Parameter{
				{Name: "page", Type: "query", Value: "1"},
			},
			FoundBy: "katana",
		},
		{
			ProjectID:   project.ID,
			HostID:      host.ID,
			URL:         "https://api.example.com/v1/login",
			Method:      "POST",
			Status:      200,
			ContentType: "application/json",
			FoundBy:     "ffuf",
		},
	}

	err = sqliteStore.BulkCreateEndpoints(ctx, endpoints)
	require.NoError(t, err)

	for _, ep := range endpoints {
		assert.NotEmpty(t, ep.ID)
	}

	listed, err := store.ListEndpoints(ctx, host.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 2)
}

func TestBulkCreateEndpoints_Empty(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	err := sqliteStore.BulkCreateEndpoints(context.Background(), []*models.Endpoint{})
	assert.NoError(t, err)
}

func TestBulkCreateFindings_Success(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	project := &models.Project{
		Name: "Finding Bulk Test", Handle: "finding-bulk", Platform: "hackerone",
		Status: models.ProjectStatusActive, Scope: models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	sqliteStore := store.(*SQLiteStore)
	findings := []*models.Finding{
		{
			ProjectID:   project.ID,
			Title:       "SQL Injection",
			Description: "SQL injection in login form",
			Severity:    models.SeverityCritical,
			Status:      models.FindingStatusNew,
			CVSS:        9.8,
			CWE:         "CWE-89",
			Steps:       []string{"Step 1", "Step 2"},
			References:  []string{"https://owasp.org/sqli"},
			FoundBy:     "nuclei",
			FoundAt:     time.Now(),
		},
		{
			ProjectID:   project.ID,
			Title:       "XSS in Search",
			Description: "Reflected XSS in search parameter",
			Severity:    models.SeverityHigh,
			Status:      models.FindingStatusNew,
			CWE:         "CWE-79",
			FoundBy:     "manual",
		},
		{
			ProjectID:   project.ID,
			Title:       "Information Disclosure",
			Description: "Server version exposed in headers",
			Severity:    models.SeverityLow,
			Status:      models.FindingStatusNew,
			FoundBy:     "httpx",
		},
	}

	err = sqliteStore.BulkCreateFindings(ctx, findings)
	require.NoError(t, err)

	for _, f := range findings {
		assert.NotEmpty(t, f.ID)
		assert.NotEmpty(t, f.Type, "Type should default to vulnerability")
		assert.NotEmpty(t, f.Confidence, "Confidence should default to medium")
		assert.False(t, f.FoundAt.IsZero(), "FoundAt should be set")
	}

	listed, err := store.ListFindings(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 3)
}

func TestBulkCreateFindings_Empty(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	sqliteStore := store.(*SQLiteStore)
	err := sqliteStore.BulkCreateFindings(context.Background(), []*models.Finding{})
	assert.NoError(t, err)
}

func TestBulkCreateFindings_DefaultValues(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	project := &models.Project{
		Name: "Defaults Test", Handle: "defaults-test", Platform: "hackerone",
		Status: models.ProjectStatusActive, Scope: models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	sqliteStore := store.(*SQLiteStore)
	// Finding with minimal fields — should get defaults
	findings := []*models.Finding{
		{
			ProjectID:   project.ID,
			Title:       "Minimal Finding",
			Description: "Just the basics",
			Severity:    models.SeverityInfo,
			Status:      models.FindingStatusNew,
		},
	}

	err = sqliteStore.BulkCreateFindings(ctx, findings)
	require.NoError(t, err)

	f := findings[0]
	assert.Equal(t, models.FindingTypeVulnerability, f.Type, "Type defaults to vulnerability")
	assert.Equal(t, models.ConfidenceMedium, f.Confidence, "Confidence defaults to medium")
	assert.False(t, f.FoundAt.IsZero(), "FoundAt defaults to current time")
	assert.False(t, f.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, f.UpdatedAt.IsZero(), "UpdatedAt should be set")
}
