package core

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/platform"
	"github.com/perplext/zerodaybuddy/internal/recon"
	"github.com/perplext/zerodaybuddy/internal/report"
	"github.com/perplext/zerodaybuddy/internal/scan"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web"
	"github.com/perplext/zerodaybuddy/pkg/config"
	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/ratelimit"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// App represents the main application
type App struct {
	config      *config.Config
	store       storage.Store
	platforms   map[string]platform.Platform
	authSvc     *auth.Service
	reconSvc    *recon.Service
	scanSvc     *scan.Service
	reportSvc   *report.Service
	webSvc      *web.Server
	logger      *utils.Logger
	rateLimiter *ratelimit.RateLimiter
}

// NewApp creates a new application instance
func NewApp(cfg *config.Config) *App {
	// Create logger with enhanced configuration
	loggerConfig := utils.LoggerConfig{
		Level:        utils.ParseLogLevel(cfg.Logging.Level),
		Format:       utils.LogFormat(cfg.Logging.Format),
		EnableColors: cfg.Logging.EnableColors,
		EnableFile:   cfg.Logging.EnableFile,
		LogDir:       cfg.LogDir,
		MaxFileSize:  cfg.Logging.MaxFileSize,
		MaxBackups:   cfg.Logging.MaxBackups,
		MaxAge:       cfg.Logging.MaxAge,
		Compress:     cfg.Logging.Compress,
	}
	
	logger := utils.NewLoggerWithConfig(loggerConfig)
	
	// Create rate limiter with config
	rlConfig := ratelimit.Config{
		DefaultRPS:      float64(cfg.Tools.DefaultRateLimit) / 60.0, // Convert per minute to per second
		DefaultBurst:    cfg.Tools.DefaultRateLimit / 6,             // 10 second burst
		CleanupInterval: 5 * time.Minute,
		Services:        ratelimit.DefaultConfig().Services,
	}
	rateLimiter := ratelimit.New(rlConfig)
	
	return &App{
		config:      cfg,
		logger:      logger,
		platforms:   make(map[string]platform.Platform),
		rateLimiter: rateLimiter,
	}
}

// Initialize initializes the application
func (a *App) Initialize(ctx context.Context) error {
	a.logger.Info("Initializing ZeroDayBuddy")
	
	// Initialize storage
	store, err := storage.NewStore(a.config.DataDir)
	if err != nil {
		return WrapCommandError(err, "initialize", map[string]interface{}{
			"dataDir": a.config.DataDir,
		})
	}
	a.store = store
	
	// Initialize platforms with rate limiter
	a.platforms["hackerone"] = platform.NewHackerOneWithRateLimiter(a.config.HackerOne, a.logger, a.rateLimiter)
	a.platforms["bugcrowd"] = platform.NewBugcrowdWithRateLimiter(a.config.Bugcrowd, a.logger, a.rateLimiter)
	
	// Initialize services
	// Create auth store from main store
	authStore := auth.NewSQLStore(store.DB())
	
	// Generate JWT secret if not provided
	jwtSecret := a.config.WebServer.JWTSecret
	if jwtSecret == "" {
		jwtSecret = "development-secret-key-change-in-production"
		a.logger.Warn("Using default JWT secret - change this in production!")
	}
	
	jwtIssuer := a.config.WebServer.JWTIssuer
	if jwtIssuer == "" {
		jwtIssuer = "zerodaybuddy"
	}
	
	a.authSvc = auth.NewService(authStore, jwtSecret, jwtIssuer, a.logger)
	a.reconSvc = recon.NewService(a.store, a.config.Tools, a.logger)
	a.scanSvc = scan.NewService(a.store, *a.config, a.logger)
	a.reportSvc = report.NewService(a.store, a.logger)
	a.webSvc = web.NewServer(a.config.WebServer, a.logger)
	
	a.logger.Info("ZeroDayBuddy initialized successfully")
	
	return nil
}

// GetAuthService returns the auth service
func (a *App) GetAuthService() *auth.Service {
	return a.authSvc
}

// ensureInitialized checks if the app is initialized and initializes it if needed
func (a *App) ensureInitialized(ctx context.Context) error {
	if a.store == nil {
		return a.Initialize(ctx)
	}
	return nil
}

// ListPrograms lists available bug bounty programs
func (a *App) ListPrograms(ctx context.Context, platformName string) error {
	if err := a.ensureInitialized(ctx); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	if platformName == "" {
		// List programs from all platforms
		for name, p := range a.platforms {
			a.logger.Info("Fetching programs from %s", name)
			programs, err := p.ListPrograms(ctx)
			if err != nil {
				a.logger.Error("Failed to fetch programs from %s: %v", name, err)
				continue
			}
			
			fmt.Printf("Programs on %s (%d):\n", name, len(programs))
			for _, program := range programs {
				fmt.Printf("- %s (%s)\n", program.Name, program.Handle)
			}
			fmt.Println()
		}
		return nil
	}
	
	// List programs from a specific platform
	p, ok := a.platforms[platformName]
	if !ok {
		return fmt.Errorf("unknown platform: %s", platformName)
	}
	
	a.logger.Info("Fetching programs from %s", platformName)
	programs, err := p.ListPrograms(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch programs from %s: %w", platformName, err)
	}
	
	fmt.Printf("Programs on %s (%d):\n", platformName, len(programs))
	for _, program := range programs {
		fmt.Printf("- %s (%s)\n", program.Name, program.Handle)
	}
	
	return nil
}

// CreateProject creates a new bug bounty project
func (a *App) CreateProject(ctx context.Context, platformName, programHandle string) error {
	if err := a.ensureInitialized(ctx); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	p, ok := a.platforms[platformName]
	if !ok {
		return pkgerrors.ValidationError("unknown platform: %s", platformName).
			WithContext("platform", platformName).
			WithContext("availablePlatforms", []string{"hackerone", "bugcrowd"})
	}
	
	a.logger.Info("Fetching program details for %s from %s", programHandle, platformName)
	program, err := p.GetProgram(ctx, programHandle)
	if err != nil {
		return pkgerrors.ExternalError(platformName, err).
			WithContext("programHandle", programHandle)
	}
	
	a.logger.Info("Creating project for %s", program.Name)
	project := &models.Project{
		Name:      program.Name,
		Handle:    program.Handle,
		Platform:  platformName,
		Type:      models.ProjectTypeBugBounty,
		StartDate: utils.CurrentTime(),
		Status:    models.ProjectStatusActive,
		Scope:     program.Scope,
	}
	
	if err := a.store.CreateProject(ctx, project); err != nil {
		// Error is already wrapped by storage layer
		return err
	}
	
	fmt.Printf("Created project for %s (%s) from %s\n", program.Name, program.Handle, platformName)
	fmt.Printf("Scope: %d in-scope targets, %d out-of-scope targets\n", 
		len(project.Scope.InScope), len(project.Scope.OutOfScope))
	
	return nil
}

// ListProjects lists all bug bounty projects
func (a *App) ListProjects(ctx context.Context) error {
	if err := a.ensureInitialized(ctx); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	projects, err := a.store.ListProjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to list projects: %w", err)
	}
	
	fmt.Printf("Projects (%d):\n", len(projects))
	for _, project := range projects {
		fmt.Printf("- %s (%s) [%s] - Started on %s\n", 
			project.Name, project.Handle, project.Status, project.StartDate.Format("2006-01-02"))
	}
	
	return nil
}

// RunRecon runs reconnaissance on a project
func (a *App) RunRecon(ctx context.Context, projectName string, concurrent int) error {
	if err := a.ensureInitialized(ctx); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	project, err := a.store.GetProjectByName(ctx, projectName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return pkgerrors.NotFoundError("project", projectName).
				WithContext("searchBy", "name")
		}
		return err
	}
	
	a.logger.Info("Running reconnaissance on project %s", project.Name)
	
	// Ensure services are initialized
	if a.reconSvc == nil {
		err := pkgerrors.New(pkgerrors.ErrorTypeInternal, "reconnaissance service not initialized")
		return err.WithContext("project", projectName)
	}
	
	// Set concurrency
	a.reconSvc.SetConcurrency(concurrent)
	
	// Run reconnaissance
	results, err := a.reconSvc.RunAll(ctx, project)
	if err != nil {
		return fmt.Errorf("failed to run reconnaissance: %w", err)
	}
	
	fmt.Printf("Reconnaissance completed for %s:\n", project.Name)
	fmt.Printf("- Subdomains discovered: %d\n", len(results.Subdomains))
	fmt.Printf("- Live hosts: %d\n", len(results.LiveHosts))
	fmt.Printf("- Endpoints discovered: %d\n", len(results.Endpoints))
	fmt.Printf("- Potential findings: %d\n", len(results.Findings))
	
	return nil
}

// RunScan runs vulnerability scanning on a project
func (a *App) RunScan(ctx context.Context, projectName, target string, concurrent int) error {
	if err := a.ensureInitialized(ctx); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	project, err := a.store.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	
	a.logger.Info("Running vulnerability scanning on project %s", project.Name)
	
	// Ensure services are initialized
	if a.scanSvc == nil {
		return fmt.Errorf("scanning service not initialized")
	}
	
	// Run vulnerability scanning
	err = a.scanSvc.ScanTarget(ctx, project.ID, target, concurrent)
	if err != nil {
		return fmt.Errorf("failed to run vulnerability scanning: %w", err)
	}
	
	// Get findings for project to display summary
	findings, err := a.store.ListFindings(ctx, project.ID)
	if err != nil {
		a.logger.Warn("Failed to list findings: %v", err)
		findings = []*models.Finding{}
	}
	
	fmt.Printf("Vulnerability scanning completed for %s:\n", project.Name)
	fmt.Printf("- Vulnerabilities found: %d\n", len(findings))
	
	// Group findings by severity
	severityCount := map[string]int{}
	for _, finding := range findings {
		severityCount[string(finding.Severity)]++
	}
	
	for severity, count := range severityCount {
		fmt.Printf("  - %s: %d\n", severity, count)
	}
	
	return nil
}

// GenerateReport generates a vulnerability report
func (a *App) GenerateReport(ctx context.Context, projectName, findingID, format, output string) error {
	if err := a.ensureInitialized(ctx); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	project, err := a.store.GetProjectByName(ctx, projectName)
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	
	a.logger.Info("Generating report for project %s", project.Name)
	
	// Ensure services are initialized
	if a.reportSvc == nil {
		return fmt.Errorf("report service not initialized")
	}
	
	// Generate report
	var reportData []byte
	if findingID == "" {
		// Create a new project report
		report, err := a.reportSvc.CreateReport(ctx, &models.Report{
			ProjectID: project.ID,
			Format:    format,
			Title:     "Project Report: " + project.Name,
		})
		if err != nil {
			return fmt.Errorf("failed to create project report: %w", err)
		}
		reportData = []byte(report.Content)
	} else {
		// Verify finding exists before creating a report for it
		if _, err := a.store.GetFinding(ctx, findingID); err != nil {
			return fmt.Errorf("failed to get finding: %w", err)
		}
		
		report, err := a.reportSvc.CreateReport(ctx, &models.Report{
			ProjectID: project.ID,
			FindingID: findingID,
			Format:    format,
			Title:     "Finding Report for Project: " + project.Name,
		})
		if err != nil {
			return fmt.Errorf("failed to create finding report: %w", err)
		}
		reportData = []byte(report.Content)
	}
	
	// Output report
	if output == "" {
		fmt.Println(string(reportData))
	} else {
		if err := utils.WriteFile(output, reportData); err != nil {
			return fmt.Errorf("failed to write report to file: %w", err)
		}
		fmt.Printf("Report written to %s\n", output)
	}
	
	return nil
}

// Serve starts the web server
func (a *App) Serve(ctx context.Context, host string, port int) error {
	if err := a.ensureInitialized(ctx); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}
	
	a.logger.Info("Starting web server on %s:%d", host, port)
	
	// Ensure services are initialized
	if a.webSvc == nil {
		return fmt.Errorf("web service not initialized")
	}
	
	// Update host and port if provided
	if host != "" {
		a.config.WebServer.Host = host
	}
	if port != 0 {
		a.config.WebServer.Port = port
	}
	
	// Start web server
	if err := a.webSvc.Start(ctx, a.config.WebServer.Host, a.config.WebServer.Port); err != nil {
		return err
	}
	
	// Block until context is cancelled
	<-ctx.Done()
	
	// Shutdown the server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return a.webSvc.Shutdown(shutdownCtx)
}

// GetConfig returns the application configuration
func (a *App) GetConfig() *config.Config {
	return a.config
}
