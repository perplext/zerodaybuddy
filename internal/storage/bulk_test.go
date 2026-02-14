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

	result, err := sqliteStore.BulkCreateHosts(ctx, hosts)
	require.NoError(t, err)
	assert.Equal(t, 3, result.Attempted)
	assert.Equal(t, 3, result.Inserted)
	assert.Equal(t, 0, result.Skipped)

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
	result, err := sqliteStore.BulkCreateHosts(context.Background(), []*models.Host{})
	assert.NoError(t, err, "empty slice should be a no-op")
	assert.Equal(t, 0, result.Attempted)
	assert.Equal(t, 0, result.Inserted)
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

	_, err = sqliteStore.BulkCreateHosts(ctx, hosts)
	require.NoError(t, err)
	assert.Equal(t, customID, hosts[0].ID, "pre-set ID should be preserved")

	// Verify the host can be retrieved with the custom ID
	retrieved, err := store.GetHost(ctx, customID)
	require.NoError(t, err)
	assert.Equal(t, "custom.example.com", retrieved.Value)
}

func TestBulkCreateHosts_SkipsDuplicates(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	project := &models.Project{
		Name: "Dup Test", Handle: "dup-test", Platform: "hackerone",
		Status: models.ProjectStatusActive, Scope: models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	sqliteStore := store.(*SQLiteStore)

	// Insert initial host
	hosts := []*models.Host{
		{
			ProjectID: project.ID,
			Type:      models.AssetTypeDomain,
			Value:     "dup.example.com",
			Status:    "active",
			FoundBy:   "subfinder",
		},
	}
	result, err := sqliteStore.BulkCreateHosts(ctx, hosts)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Inserted)

	// Insert batch with a duplicate and a new host
	batch2 := []*models.Host{
		{
			ProjectID: project.ID,
			Type:      models.AssetTypeDomain,
			Value:     "dup.example.com", // duplicate
			Status:    "active",
			FoundBy:   "amass",
		},
		{
			ProjectID: project.ID,
			Type:      models.AssetTypeDomain,
			Value:     "new.example.com", // new
			Status:    "active",
			FoundBy:   "amass",
		},
	}
	result, err = sqliteStore.BulkCreateHosts(ctx, batch2)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Attempted)
	assert.Equal(t, 1, result.Inserted)
	assert.Equal(t, 1, result.Skipped)

	// Verify total is 2, not 3
	listed, err := store.ListHosts(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, listed, 2)
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

	result, err := sqliteStore.BulkCreateEndpoints(ctx, endpoints)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Inserted)
	assert.Equal(t, 0, result.Skipped)

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
	result, err := sqliteStore.BulkCreateEndpoints(context.Background(), []*models.Endpoint{})
	assert.NoError(t, err)
	assert.Equal(t, 0, result.Attempted)
}

func TestBulkCreateEndpoints_SkipsDuplicates(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	project := &models.Project{
		Name: "EP Dup Test", Handle: "ep-dup", Platform: "hackerone",
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

	// Insert initial endpoint
	eps := []*models.Endpoint{
		{ProjectID: project.ID, HostID: host.ID, URL: "https://api.example.com/users", Method: "GET", FoundBy: "katana"},
	}
	_, err = sqliteStore.BulkCreateEndpoints(ctx, eps)
	require.NoError(t, err)

	// Insert batch with duplicate (same host_id + url + method) and new endpoint
	batch2 := []*models.Endpoint{
		{ProjectID: project.ID, HostID: host.ID, URL: "https://api.example.com/users", Method: "GET", FoundBy: "katana"}, // dup
		{ProjectID: project.ID, HostID: host.ID, URL: "https://api.example.com/users", Method: "POST", FoundBy: "ffuf"},  // new (different method)
	}
	result, err := sqliteStore.BulkCreateEndpoints(ctx, batch2)
	require.NoError(t, err)
	assert.Equal(t, 2, result.Attempted)
	assert.Equal(t, 1, result.Inserted)
	assert.Equal(t, 1, result.Skipped)
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

	result, err := sqliteStore.BulkCreateFindings(ctx, findings)
	require.NoError(t, err)
	assert.Equal(t, 3, result.Inserted)
	assert.Equal(t, 0, result.Skipped)

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
	result, err := sqliteStore.BulkCreateFindings(context.Background(), []*models.Finding{})
	assert.NoError(t, err)
	assert.Equal(t, 0, result.Attempted)
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

	_, err = sqliteStore.BulkCreateFindings(ctx, findings)
	require.NoError(t, err)

	f := findings[0]
	assert.Equal(t, models.FindingTypeVulnerability, f.Type, "Type defaults to vulnerability")
	assert.Equal(t, models.ConfidenceMedium, f.Confidence, "Confidence defaults to medium")
	assert.False(t, f.FoundAt.IsZero(), "FoundAt defaults to current time")
	assert.False(t, f.CreatedAt.IsZero(), "CreatedAt should be set")
	assert.False(t, f.UpdatedAt.IsZero(), "UpdatedAt should be set")
}
