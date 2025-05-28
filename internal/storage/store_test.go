package storage

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestStore(t *testing.T) (Store, func()) {
	tempDir, err := os.MkdirTemp("", "zerodaybuddy-test-*")
	require.NoError(t, err)

	store, err := NewStore(tempDir)
	require.NoError(t, err)

	cleanup := func() {
		store.Close()
		os.RemoveAll(tempDir)
	}

	return store, cleanup
}

func TestProjectCRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Test Create
	project := &models.Project{
		Name:        "Test Project",
		Handle:      "test-project",
		Platform:    "hackerone",
		Description: "Test description",
		StartDate:   time.Now(),
		Status:      models.ProjectStatusActive,
		Scope: models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
			},
		},
		Notes: "Test notes",
	}

	err := store.CreateProject(ctx, project)
	require.NoError(t, err)
	assert.NotEmpty(t, project.ID)

	// Test Get
	retrieved, err := store.GetProject(ctx, project.ID)
	require.NoError(t, err)
	assert.Equal(t, project.Name, retrieved.Name)
	assert.Equal(t, project.Handle, retrieved.Handle)
	assert.Equal(t, project.Platform, retrieved.Platform)
	assert.Equal(t, project.Description, retrieved.Description)
	assert.Equal(t, project.Status, retrieved.Status)
	assert.Len(t, retrieved.Scope.InScope, 1)
	assert.Equal(t, "example.com", retrieved.Scope.InScope[0].Value)

	// Test GetByName
	byName, err := store.GetProjectByName(ctx, project.Name)
	require.NoError(t, err)
	assert.Equal(t, project.ID, byName.ID)

	// Test Update
	retrieved.Description = "Updated description"
	retrieved.Status = models.ProjectStatusCompleted
	err = store.UpdateProject(ctx, retrieved)
	require.NoError(t, err)

	updated, err := store.GetProject(ctx, project.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated description", updated.Description)
	assert.Equal(t, models.ProjectStatusCompleted, updated.Status)

	// Test List
	projects, err := store.ListProjects(ctx)
	require.NoError(t, err)
	assert.Len(t, projects, 1)
	assert.Equal(t, project.ID, projects[0].ID)

	// Test Delete
	err = store.DeleteProject(ctx, project.ID)
	require.NoError(t, err)

	_, err = store.GetProject(ctx, project.ID)
	assert.Error(t, err) // Project should not be found after deletion
}

func TestHostCRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create a project first
	project := &models.Project{
		Name:     "Test Project",
		Handle:   "test-project",
		Platform: "hackerone",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Test Create Host
	host := &models.Host{
		ProjectID:    project.ID,
		Type:         models.AssetTypeDomain,
		Value:        "test.example.com",
		IP:           "192.168.1.1",
		Status:       "active",
		Title:        "Test Host",
		Technologies: []string{"nginx", "php"},
		Ports:        []int{80, 443},
		Headers: map[string]string{
			"Server": "nginx/1.19.0",
		},
		FoundBy: "subfinder",
	}

	err = store.CreateHost(ctx, host)
	require.NoError(t, err)
	assert.NotEmpty(t, host.ID)

	// Test Get Host
	retrieved, err := store.GetHost(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, host.Value, retrieved.Value)
	assert.Equal(t, host.IP, retrieved.IP)
	assert.ElementsMatch(t, host.Technologies, retrieved.Technologies)
	assert.ElementsMatch(t, host.Ports, retrieved.Ports)
	assert.Equal(t, "nginx/1.19.0", retrieved.Headers["Server"])

	// Test Update Host
	retrieved.Status = "inactive"
	retrieved.Technologies = append(retrieved.Technologies, "mysql")
	err = store.UpdateHost(ctx, retrieved)
	require.NoError(t, err)

	updated, err := store.GetHost(ctx, host.ID)
	require.NoError(t, err)
	assert.Equal(t, "inactive", updated.Status)
	assert.Contains(t, updated.Technologies, "mysql")

	// Test List Hosts
	hosts, err := store.ListHosts(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, hosts, 1)
	assert.Equal(t, host.ID, hosts[0].ID)

	// Test Delete Host
	err = store.DeleteHost(ctx, host.ID)
	require.NoError(t, err)

	_, err = store.GetHost(ctx, host.ID)
	assert.Error(t, err) // Host should not be found after deletion
}

func TestEndpointCRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create project and host first
	project := &models.Project{
		Name:     "Test Project",
		Handle:   "test-project",
		Platform: "hackerone",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	host := &models.Host{
		ProjectID: project.ID,
		Type:      models.AssetTypeDomain,
		Value:     "test.example.com",
		Status:    "active",
		FoundBy:   "subfinder",
	}
	err = store.CreateHost(ctx, host)
	require.NoError(t, err)

	// Test Create Endpoint
	endpoint := &models.Endpoint{
		ProjectID:   project.ID,
		HostID:      host.ID,
		URL:         "https://test.example.com/api/v1/users",
		Method:      "GET",
		Status:      200,
		ContentType: "application/json",
		Title:       "Users API",
		Parameters: []models.Parameter{
			{Name: "page", Type: "query", Value: "1"},
			{Name: "limit", Type: "query", Value: "10"},
		},
		FoundBy: "katana",
	}

	err = store.CreateEndpoint(ctx, endpoint)
	require.NoError(t, err)
	assert.NotEmpty(t, endpoint.ID)

	// Test Get Endpoint
	retrieved, err := store.GetEndpoint(ctx, endpoint.ID)
	require.NoError(t, err)
	assert.Equal(t, endpoint.URL, retrieved.URL)
	assert.Equal(t, endpoint.Method, retrieved.Method)
	assert.Len(t, retrieved.Parameters, 2)
	assert.Equal(t, "page", retrieved.Parameters[0].Name)

	// Test Update Endpoint
	retrieved.Status = 404
	retrieved.Title = "Deprecated API"
	err = store.UpdateEndpoint(ctx, retrieved)
	require.NoError(t, err)

	updated, err := store.GetEndpoint(ctx, endpoint.ID)
	require.NoError(t, err)
	assert.Equal(t, 404, updated.Status)
	assert.Equal(t, "Deprecated API", updated.Title)

	// Test List Endpoints
	endpoints, err := store.ListEndpoints(ctx, host.ID)
	require.NoError(t, err)
	assert.Len(t, endpoints, 1)
	assert.Equal(t, endpoint.ID, endpoints[0].ID)

	// Test Delete Endpoint
	err = store.DeleteEndpoint(ctx, endpoint.ID)
	require.NoError(t, err)

	_, err = store.GetEndpoint(ctx, endpoint.ID)
	assert.Error(t, err) // Endpoint should not be found after deletion
}

func TestFindingCRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create project first
	project := &models.Project{
		Name:     "Test Project",
		Handle:   "test-project",
		Platform: "hackerone",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Test Create Finding
	finding := &models.Finding{
		ProjectID:   project.ID,
		Title:       "SQL Injection",
		Description: "SQL injection vulnerability found",
		Details:     "Detailed explanation",
		Severity:    models.SeverityHigh,
		Status:      models.FindingStatusNew,
		CVSS:        7.5,
		CWE:         "CWE-89",
		Steps:       []string{"Step 1", "Step 2", "Step 3"},
		Evidence: []models.Evidence{
			{Type: "request", Data: "GET /api/users?id=1' OR '1'='1"},
			{Type: "response", Data: "Database error"},
		},
		Impact:      "High impact on data confidentiality",
		Remediation: "Use parameterized queries",
		References:  []string{"https://owasp.org/sql-injection"},
		FoundBy:     "manual",
		FoundAt:     time.Now(),
	}

	err = store.CreateFinding(ctx, finding)
	require.NoError(t, err)
	assert.NotEmpty(t, finding.ID)

	// Test Get Finding
	retrieved, err := store.GetFinding(ctx, finding.ID)
	require.NoError(t, err)
	assert.Equal(t, finding.Title, retrieved.Title)
	assert.Equal(t, finding.Severity, retrieved.Severity)
	assert.Len(t, retrieved.Steps, 3)
	// Evidence is now an interface, check if it's a slice
	if evidence, ok := retrieved.Evidence.([]interface{}); ok {
		assert.Len(t, evidence, 2)
	} else if evidence, ok := retrieved.Evidence.([]models.Evidence); ok {
		assert.Len(t, evidence, 2)
		assert.Equal(t, "request", evidence[0].Type)
	}

	// Test Update Finding
	retrieved.Status = models.FindingStatusConfirmed
	retrieved.Severity = models.SeverityCritical
	err = store.UpdateFinding(ctx, retrieved)
	require.NoError(t, err)

	updated, err := store.GetFinding(ctx, finding.ID)
	require.NoError(t, err)
	assert.Equal(t, models.FindingStatusConfirmed, updated.Status)
	assert.Equal(t, models.SeverityCritical, updated.Severity)

	// Test List Findings
	findings, err := store.ListFindings(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, finding.ID, findings[0].ID)

	// Test Delete Finding
	err = store.DeleteFinding(ctx, finding.ID)
	require.NoError(t, err)

	_, err = store.GetFinding(ctx, finding.ID)
	assert.Error(t, err) // Finding should not be found after deletion
}

func TestTaskCRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create project first
	project := &models.Project{
		Name:     "Test Project",
		Handle:   "test-project",
		Platform: "hackerone",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Test Create Task
	task := &models.Task{
		ProjectID:   project.ID,
		Type:        "recon",
		Name:        "Subdomain Enumeration",
		Description: "Enumerate subdomains for example.com",
		Status:      "pending",
		Priority:    "high",
		AssignedTo:  "scanner",
		Progress:    0,
		Details: map[string]interface{}{
			"target": "example.com",
			"tools":  []string{"subfinder", "amass"},
		},
	}

	err = store.CreateTask(ctx, task)
	require.NoError(t, err)
	assert.NotEmpty(t, task.ID)

	// Test Get Task
	retrieved, err := store.GetTask(ctx, task.ID)
	require.NoError(t, err)
	assert.Equal(t, task.Name, retrieved.Name)
	assert.Equal(t, task.Type, retrieved.Type)
	assert.Equal(t, "example.com", retrieved.Details["target"])

	// Test Update Task
	retrieved.Status = "in_progress"
	retrieved.Progress = 50
	err = store.UpdateTask(ctx, retrieved)
	require.NoError(t, err)

	updated, err := store.GetTask(ctx, task.ID)
	require.NoError(t, err)
	assert.Equal(t, "in_progress", updated.Status)
	assert.Equal(t, 50, updated.Progress)

	// Test List Tasks
	tasks, err := store.ListTasks(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, tasks, 1)
	assert.Equal(t, task.ID, tasks[0].ID)

	// Test Delete Task
	err = store.DeleteTask(ctx, task.ID)
	require.NoError(t, err)

	_, err = store.GetTask(ctx, task.ID)
	assert.Error(t, err) // Task should not be found after deletion
}

func TestReportCRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create project first
	project := &models.Project{
		Name:     "Test Project",
		Handle:   "test-project",
		Platform: "hackerone",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Test Create Report
	report := &models.Report{
		ProjectID: project.ID,
		FindingID: "", // No finding associated
		Title:     "Security Assessment Report",
		Format:    "markdown",
		Content:   "# Security Report\n\nVulnerabilities found...",
		Metadata: map[string]interface{}{
			"author": "ZeroDayBuddy",
			"date":   time.Now().Format("2006-01-02"),
		},
	}

	created, err := store.CreateReport(ctx, report)
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)

	// Test Get Report
	retrieved, err := store.GetReport(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, report.Title, retrieved.Title)
	assert.Equal(t, report.Format, retrieved.Format)
	assert.Equal(t, "ZeroDayBuddy", retrieved.Metadata["author"])

	// Test List Reports
	reports, err := store.ListReports(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, reports, 1)
	assert.Equal(t, created.ID, reports[0].ID)

	// Test Delete Report
	err = store.DeleteReport(ctx, created.ID)
	require.NoError(t, err)

	_, err = store.GetReport(ctx, created.ID)
	assert.Error(t, err) // Report should not be found after deletion
}

func TestConcurrency(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create a project
	project := &models.Project{
		Name:     "Concurrent Project",
		Handle:   "concurrent",
		Platform: "hackerone",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err := store.CreateProject(ctx, project)
	require.NoError(t, err)

	// Test concurrent host creation
	done := make(chan bool, 10)
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(index int) {
			host := &models.Host{
				ProjectID: project.ID,
				Type:      models.AssetTypeDomain,
				Value:     fmt.Sprintf("host%d.example.com", index),
				Status:    "active",
				FoundBy:   "test",
			}
			if err := store.CreateHost(ctx, host); err != nil {
				errors <- err
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
	close(errors)

	// Check for errors
	for err := range errors {
		t.Fatalf("Concurrent operation failed: %v", err)
	}

	// Verify all hosts were created
	hosts, err := store.ListHosts(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, hosts, 10)
}

func TestTransactionRollback(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Test that duplicate project names cause an error
	project1 := &models.Project{
		Name:     "Unique Project",
		Handle:   "unique1",
		Platform: "hackerone",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err := store.CreateProject(ctx, project1)
	require.NoError(t, err)

	// Try to create another project with the same name
	project2 := &models.Project{
		Name:     "Unique Project", // Same name
		Handle:   "unique2",
		Platform: "bugcrowd",
		Status:   models.ProjectStatusActive,
		Scope:    models.Scope{},
	}
	err = store.CreateProject(ctx, project2)
	assert.Error(t, err) // Should fail due to unique constraint

	// Verify only one project exists
	projects, err := store.ListProjects(ctx)
	require.NoError(t, err)
	assert.Len(t, projects, 1)
}