package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/perplext/zerodaybuddy/internal/core"
	"github.com/perplext/zerodaybuddy/pkg/config"
	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/perplext/zerodaybuddy/pkg/validation"
	"github.com/spf13/cobra"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		// Create a basic logger for initialization errors
		logger := utils.NewLogger("", false)
		core.ExitOnError(
			pkgerrors.InternalError("failed to load configuration", err),
			logger,
		)
	}

	// Create logger from config
	logger := utils.NewLogger(cfg.LogDir, cfg.Debug)

	rootCmd := createRootCommand(cfg)
	if err := rootCmd.Execute(); err != nil {
		// Cobra already prints usage on flag errors, just exit
		if strings.Contains(err.Error(), "unknown flag") || 
		   strings.Contains(err.Error(), "invalid argument") {
			os.Exit(1)
		}
		// For other errors, use our error handling
		core.ExitOnError(err, logger)
	}
}

func createRootCommand(cfg *config.Config) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "zerodaybuddy",
		Short: "A comprehensive bug bounty assistant tool",
		Long: `ZeroDayBuddy is a comprehensive bug bounty assistant tool that streamlines 
the process of taking on new bounty programs and conducting end-to-end 
reconnaissance and testing.`,
	}

	// Initialize the application
	app := core.NewApp(cfg)

	// Add commands
	rootCmd.AddCommand(
		createInitCommand(app),
		createListProgramsCommand(app),
		createProjectCommand(app),
		createReconCommand(app),
		createScanCommand(app),
		createReportCommand(app),
		createServeCommand(app),
		createMigrateCommand(app),
		createVersionCommand(),
	)

	return rootCmd
}

func createInitCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize ZeroDayBuddy configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.Initialize(cmd.Context())
		},
	}
	return cmd
}

func createListProgramsCommand(app *core.App) *cobra.Command {
	var platform string

	cmd := &cobra.Command{
		Use:   "list-programs",
		Short: "List available bug bounty programs",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate platform if provided
			if platform != "" {
				if err := validation.Platform(platform); err != nil {
					return fmt.Errorf("invalid platform: %w", err)
				}
			}
			return app.ListPrograms(cmd.Context(), platform)
		},
	}

	cmd.Flags().StringVarP(&platform, "platform", "p", "", "Bug bounty platform (hackerone, bugcrowd)")
	
	return cmd
}

func createProjectCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "project",
		Short: "Manage bug bounty projects",
	}

	cmd.AddCommand(createProjectCreateCommand(app))
	cmd.AddCommand(createProjectListCommand(app))
	
	return cmd
}

func createProjectCreateCommand(app *core.App) *cobra.Command {
	var platform, program string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new bug bounty project",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate platform
			if err := validation.Platform(platform); err != nil {
				return fmt.Errorf("invalid platform: %w", err)
			}
			
			// Validate program handle
			if err := validation.Handle(program); err != nil {
				return fmt.Errorf("invalid program handle: %w", err)
			}
			
			return app.CreateProject(cmd.Context(), platform, program)
		},
	}

	cmd.Flags().StringVarP(&platform, "platform", "p", "", "Bug bounty platform (hackerone, bugcrowd)")
	cmd.Flags().StringVarP(&program, "program", "n", "", "Program name or handle")
	cmd.MarkFlagRequired("platform")
	cmd.MarkFlagRequired("program")
	
	return cmd
}

func createProjectListCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all bug bounty projects",
		RunE: func(cmd *cobra.Command, args []string) error {
			return app.ListProjects(cmd.Context())
		},
	}
	
	return cmd
}

func createReconCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Manage reconnaissance tasks",
	}

	cmd.AddCommand(createReconRunCommand(app))
	
	return cmd
}

func createReconRunCommand(app *core.App) *cobra.Command {
	var project string
	var concurrent int

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run reconnaissance on a project",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate project name
			if err := validation.ProjectName(project); err != nil {
				return fmt.Errorf("invalid project name: %w", err)
			}
			
			// Validate concurrency
			if err := validation.Concurrency(concurrent); err != nil {
				return fmt.Errorf("invalid concurrency: %w", err)
			}
			
			return app.RunRecon(cmd.Context(), project, concurrent)
		},
	}

	cmd.Flags().StringVarP(&project, "project", "p", "", "Project name")
	cmd.Flags().IntVarP(&concurrent, "concurrent", "c", 10, "Maximum concurrent tasks")
	cmd.MarkFlagRequired("project")
	
	return cmd
}

func createScanCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Manage vulnerability scanning tasks",
	}

	cmd.AddCommand(createScanRunCommand(app))
	
	return cmd
}

func createScanRunCommand(app *core.App) *cobra.Command {
	var project string
	var target string
	var concurrent int

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run vulnerability scanning on a project",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate project name
			if err := validation.ProjectName(project); err != nil {
				return fmt.Errorf("invalid project name: %w", err)
			}
			
			// Validate target URL if provided
			if target != "" {
				if err := validation.ScopeURL(target, false); err != nil {
					return fmt.Errorf("invalid target: %w", err)
				}
			}
			
			// Validate concurrency
			if err := validation.Concurrency(concurrent); err != nil {
				return fmt.Errorf("invalid concurrency: %w", err)
			}
			
			return app.RunScan(cmd.Context(), project, target, concurrent)
		},
	}

	cmd.Flags().StringVarP(&project, "project", "p", "", "Project name")
	cmd.Flags().StringVarP(&target, "target", "t", "", "Target URL or asset (optional, scans all if not specified)")
	cmd.Flags().IntVarP(&concurrent, "concurrent", "c", 5, "Maximum concurrent tasks")
	cmd.MarkFlagRequired("project")
	
	return cmd
}

func createReportCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Manage vulnerability reports",
	}

	cmd.AddCommand(createReportGenerateCommand(app))
	
	return cmd
}

func createReportGenerateCommand(app *core.App) *cobra.Command {
	var project, finding, format, output string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a vulnerability report",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate project name
			if err := validation.ProjectName(project); err != nil {
				return fmt.Errorf("invalid project name: %w", err)
			}
			
			// Validate finding ID if provided
			if finding != "" {
				if err := validation.UUID(finding); err != nil {
					return fmt.Errorf("invalid finding ID: %w", err)
				}
			}
			
			// Validate report format
			if err := validation.ReportFormat(format); err != nil {
				return fmt.Errorf("invalid format: %w", err)
			}
			
			// Validate output path
			if err := validation.FilePath(output); err != nil {
				return fmt.Errorf("invalid output path: %w", err)
			}
			
			return app.GenerateReport(cmd.Context(), project, finding, format, output)
		},
	}

	cmd.Flags().StringVarP(&project, "project", "p", "", "Project name")
	cmd.Flags().StringVarP(&finding, "finding", "f", "", "Finding ID (optional, generates report for all findings if not specified)")
	cmd.Flags().StringVarP(&format, "format", "m", "markdown", "Report format (markdown, pdf)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (optional, outputs to stdout if not specified)")
	cmd.MarkFlagRequired("project")
	
	return cmd
}

func createServeCommand(app *core.App) *cobra.Command {
	var port int
	var host string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the ZeroDayBuddy web server",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate port
			if err := validation.Port(port); err != nil {
				return fmt.Errorf("invalid port: %w", err)
			}
			
			// Validate host
			if err := validation.Host(host); err != nil {
				return fmt.Errorf("invalid host: %w", err)
			}
			
			return app.Serve(cmd.Context(), host, port)
		},
	}

	cmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on")
	cmd.Flags().StringVarP(&host, "host", "H", "localhost", "Host to bind to")
	
	return cmd
}
