package core

import (
	"context"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/pkg/config"
	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestConfig() *config.Config {
	return &config.Config{
		DataDir: ":memory:",
		LogDir:  "",
		Logging: config.LoggingConfig{
			Level:        "info",
			Format:       "text",
			EnableColors: false,
			EnableFile:   false,
		},
		Tools: config.ToolsConfig{
			DefaultRateLimit: 60,
		},
		HackerOne: config.HackerOneConfig{
			APIKey: "test-hackerone-key",
		},
		Bugcrowd: config.BugcrowdConfig{
			Email:       "test@example.com",
			CookieValue: "test-cookie",
		},
		WebServer: config.WebServerConfig{
			Host:      "localhost",
			Port:      8080,
			JWTSecret: "test-secret",
			JWTIssuer: "test-issuer",
		},
	}
}

func TestNewApp(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	assert.NotNil(t, app)
	assert.Equal(t, cfg, app.config)
	assert.NotNil(t, app.logger)
	assert.NotNil(t, app.platforms)
	assert.NotNil(t, app.rateLimiter)
}

func TestAppInitialize(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	
	require.NoError(t, err)
	assert.NotNil(t, app.store)
	assert.NotNil(t, app.authSvc)
	assert.NotNil(t, app.reconSvc)
	assert.NotNil(t, app.scanSvc)
	assert.NotNil(t, app.reportSvc)
	assert.NotNil(t, app.webSvc)
	assert.Len(t, app.platforms, 2)
	assert.Contains(t, app.platforms, "hackerone")
	assert.Contains(t, app.platforms, "bugcrowd")
}

func TestAppInitializeWithoutJWTSecret(t *testing.T) {
	cfg := getTestConfig()
	cfg.WebServer.JWTSecret = ""
	cfg.WebServer.JWTIssuer = ""
	
	app := NewApp(cfg)
	ctx := context.Background()
	err := app.Initialize(ctx)
	
	require.NoError(t, err)
	assert.NotNil(t, app.authSvc)
}

func TestGetAuthService(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	require.NoError(t, err)
	
	authSvc := app.GetAuthService()
	assert.NotNil(t, authSvc)
	assert.Equal(t, app.authSvc, authSvc)
}

func TestGetConfig(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	returnedCfg := app.GetConfig()
	assert.Equal(t, cfg, returnedCfg)
}

func TestListProgramsUnknownPlatform(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	require.NoError(t, err)
	
	err = app.ListPrograms(ctx, "unknown-platform")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown platform")
}

func TestCreateProjectUnknownPlatform(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	require.NoError(t, err)
	
	err = app.CreateProject(ctx, "unknown-platform", "test-handle")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown platform")
}

func TestListProjects(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	require.NoError(t, err)
	
	// Should not error even with no projects
	err = app.ListProjects(ctx)
	assert.NoError(t, err)
}

func TestRunReconProjectNotFound(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	require.NoError(t, err)
	
	err = app.RunRecon(ctx, "non-existent-project", 5)
	assert.Error(t, err)
	// The error should be wrapped as a NotFoundError
	errType, ok := pkgerrors.GetType(err)
	if ok {
		assert.Equal(t, pkgerrors.ErrorTypeNotFound, errType)
	} else {
		// Fallback for raw SQL error
		assert.Contains(t, err.Error(), "no rows")
	}
}

func TestRunScanProjectNotFound(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	require.NoError(t, err)
	
	err = app.RunScan(ctx, "non-existent-project", "", 5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get project")
}

func TestGenerateReportProjectNotFound(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	require.NoError(t, err)
	
	err = app.GenerateReport(ctx, "non-existent-project", "", "markdown", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get project")
}

func TestServeWithCustomHostPort(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	ctx := context.Background()
	err := app.Initialize(ctx)
	require.NoError(t, err)
	
	// Update config through Serve method
	customHost := "0.0.0.0"
	customPort := 9090
	
	// We can't actually start the server in tests, but we can verify config update
	// by checking the config after calling serve with cancel context
	cancelCtx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately
	
	_ = app.Serve(cancelCtx, customHost, customPort)
	
	assert.Equal(t, customHost, app.config.WebServer.Host)
	assert.Equal(t, customPort, app.config.WebServer.Port)
}

func TestServeWithoutInit(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	// Don't initialize, webSvc should be nil
	ctx := context.Background()
	err := app.Serve(ctx, "", 0)
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "web service not initialized")
}

func TestRunReconWithoutInit(t *testing.T) {
	cfg := getTestConfig()
	app := NewApp(cfg)
	
	// Create a fresh store instance for this test
	tempDir := t.TempDir()
	store, err := storage.NewStore(tempDir)
	require.NoError(t, err)
	app.store = store
	// Ensure services are nil
	app.reconSvc = nil
	
	// Create a test project with unique name
	ctx := context.Background()
	project := &models.Project{
		Name:      "Recon Test Project",
		Handle:    "recon-test-project",
		Platform:  "hackerone",
		StartDate: time.Now(),
		Status:    models.ProjectStatusActive,
	}
	err = app.store.CreateProject(ctx, project)
	require.NoError(t, err)
	
	// Try to run recon without initializing services
	err = app.RunRecon(ctx, "Recon Test Project", 5)
	assert.Error(t, err)
	// Check for internal error type
	errType, ok := pkgerrors.GetType(err)
	assert.True(t, ok)
	assert.Equal(t, pkgerrors.ErrorTypeInternal, errType)
}