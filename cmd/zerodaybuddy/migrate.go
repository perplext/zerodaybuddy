package main

import (
	"fmt"

	"github.com/perplext/zerodaybuddy/internal/core"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/storage/migrations"
	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/validation"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/cobra"
)

func createMigrateCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Manage database migrations",
	}

	cmd.AddCommand(
		createMigrateUpCommand(app),
		createMigrateDownCommand(app),
		createMigrateStatusCommand(app),
		createMigrateCreateCommand(app),
	)

	return cmd
}

func createMigrateUpCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up",
		Short: "Apply all pending migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDatabase(app)
			if err != nil {
				return err
			}
			defer db.Close()

			migrator := migrations.NewMigrator(db)
			
			fmt.Println("Running migrations...")
			if err := migrator.Migrate(cmd.Context()); err != nil {
				return err
			}
			
			fmt.Println("All migrations completed successfully")
			return nil
		},
	}
	return cmd
}

func createMigrateDownCommand(app *core.App) *cobra.Command {
	var steps int

	cmd := &cobra.Command{
		Use:   "down",
		Short: "Rollback migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate steps
			if err := validation.PositiveInteger(steps, "steps"); err != nil {
				return fmt.Errorf("invalid steps: %w", err)
			}
			
			if steps > 100 {
				return fmt.Errorf("too many steps: maximum 100 migrations can be rolled back at once")
			}
			
			db, err := openDatabase(app)
			if err != nil {
				return err
			}
			defer db.Close()

			migrator := migrations.NewMigrator(db)
			
			fmt.Printf("Rolling back %d migration(s)...\n", steps)
			if err := migrator.Rollback(cmd.Context(), steps); err != nil {
				return err
			}
			
			fmt.Println("Rollback completed successfully")
			return nil
		},
	}

	cmd.Flags().IntVarP(&steps, "steps", "n", 1, "Number of migrations to rollback")
	
	return cmd
}

func createMigrateStatusCommand(app *core.App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show migration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			db, err := openDatabase(app)
			if err != nil {
				return err
			}
			defer db.Close()

			migrator := migrations.NewMigrator(db)
			
			// Initialize migrations table if needed
			if err := migrator.Initialize(cmd.Context()); err != nil {
				return err
			}
			
			// Get applied migrations
			applied, err := migrator.GetAppliedMigrations(cmd.Context())
			if err != nil {
				return err
			}
			
			// Get all migrations
			all, err := migrator.LoadMigrations()
			if err != nil {
				return err
			}
			
			// Create map of applied migrations
			appliedMap := make(map[int]migrations.Migration)
			for _, m := range applied {
				appliedMap[m.Version] = m
			}
			
			// Display status
			fmt.Println("Migration Status:")
			fmt.Println("=================")
			
			for _, migration := range all {
				status := "Pending"
				var appliedAt string
				
				if applied, ok := appliedMap[migration.Version]; ok {
					status = "Applied"
					appliedAt = applied.AppliedAt.Format("2006-01-02 15:04:05")
				}
				
				fmt.Printf("%03d %-30s %-10s %s\n", 
					migration.Version, 
					migration.Name, 
					status,
					appliedAt,
				)
			}
			
			// Show summary
			pending := len(all) - len(applied)
			fmt.Printf("\nTotal: %d migrations (%d applied, %d pending)\n", 
				len(all), len(applied), pending)
			
			return nil
		},
	}
	return cmd
}

func createMigrateCreateCommand(app *core.App) *cobra.Command {
	var name string

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new migration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return pkgerrors.ValidationError("migration name is required")
			}
			
			// Validate name format
			if err := validation.MigrationName(name); err != nil {
				return fmt.Errorf("invalid migration name: %w", err)
			}
			
			// Get next version number
			db, err := openDatabase(app)
			if err != nil {
				return err
			}
			defer db.Close()
			
			migrator := migrations.NewMigrator(db)
			all, err := migrator.LoadMigrations()
			if err != nil {
				return err
			}
			
			nextVersion := 1
			if len(all) > 0 {
				nextVersion = all[len(all)-1].Version + 1
			}
			
			// Create migration file
			filename := fmt.Sprintf("%03d_%s.sql", nextVersion, name)
			filepath := fmt.Sprintf("internal/storage/migrations/sql/%s", filename)
			
			template := `-- Description: %s

-- +migrate Up
-- Write your UP migration here

-- +migrate Down
-- Write your DOWN migration here
`
			
			content := fmt.Sprintf(template, name)
			
			// Note: In a real implementation, you would write this file
			// For now, just print the information
			fmt.Printf("Migration file to create: %s\n", filepath)
			fmt.Printf("Content:\n%s\n", content)
			fmt.Println("\nNote: Please create this file manually in your migration directory")
			
			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "Migration name (e.g., add_user_table)")
	cmd.MarkFlagRequired("name")
	
	return cmd
}

// openDatabase opens a database connection for migrations
func openDatabase(app *core.App) (*sqlx.DB, error) {
	// Get database path from config
	dbPath := fmt.Sprintf("%s/zerodaybuddy.db", app.GetConfig().DataDir)

	// Open database connection
	db, err := sqlx.Connect("sqlite3", dbPath)
	if err != nil {
		return nil, pkgerrors.InternalError("failed to connect to database", err).
			WithContext("dbPath", dbPath)
	}

	// Apply shared SQLite PRAGMAs
	if err := storage.ConfigureSQLite(db); err != nil {
		db.Close()
		return nil, pkgerrors.InternalError("failed to configure database", err).
			WithContext("dbPath", dbPath)
	}

	return db, nil
}