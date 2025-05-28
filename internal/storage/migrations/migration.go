package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/jmoiron/sqlx"
)

//go:embed sql/*.sql
var migrationFiles embed.FS

// Migration represents a database migration
type Migration struct {
	ID          string
	Version     int
	Name        string
	Description string
	Checksum    string
	AppliedAt   time.Time
	ExecutionTime time.Duration
}

// MigrationFile represents a migration file
type MigrationFile struct {
	Version     int
	Name        string
	Description string
	UpSQL       string
	DownSQL     string
	Checksum    string
}

// Migrator handles database migrations
type Migrator struct {
	db *sqlx.DB
}

// NewMigrator creates a new migrator instance
func NewMigrator(db *sqlx.DB) *Migrator {
	return &Migrator{db: db}
}

// Initialize creates the migrations table if it doesn't exist
func (m *Migrator) Initialize(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		id TEXT PRIMARY KEY,
		version INTEGER NOT NULL UNIQUE,
		name TEXT NOT NULL,
		description TEXT,
		checksum TEXT NOT NULL,
		applied_at TIMESTAMP NOT NULL,
		execution_time_ms INTEGER NOT NULL
	);
	
	CREATE INDEX IF NOT EXISTS idx_migrations_version ON schema_migrations(version);
	`
	
	if _, err := m.db.ExecContext(ctx, query); err != nil {
		return pkgerrors.InternalError("failed to create migrations table", err)
	}
	
	return nil
}

// GetAppliedMigrations returns all applied migrations
func (m *Migrator) GetAppliedMigrations(ctx context.Context) ([]Migration, error) {
	var migrations []Migration
	
	query := `
	SELECT id, version, name, description, checksum, applied_at, execution_time_ms
	FROM schema_migrations
	ORDER BY version ASC
	`
	
	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, pkgerrors.InternalError("failed to query migrations", err)
	}
	defer rows.Close()
	
	for rows.Next() {
		var migration Migration
		var execTimeMs int64
		
		err := rows.Scan(
			&migration.ID,
			&migration.Version,
			&migration.Name,
			&migration.Description,
			&migration.Checksum,
			&migration.AppliedAt,
			&execTimeMs,
		)
		if err != nil {
			return nil, pkgerrors.InternalError("failed to scan migration", err)
		}
		
		migration.ExecutionTime = time.Duration(execTimeMs) * time.Millisecond
		migrations = append(migrations, migration)
	}
	
	if err := rows.Err(); err != nil {
		return nil, pkgerrors.InternalError("failed to iterate migrations", err)
	}
	
	return migrations, nil
}

// GetLatestVersion returns the latest applied migration version
func (m *Migrator) GetLatestVersion(ctx context.Context) (int, error) {
	var version sql.NullInt64
	
	query := `SELECT MAX(version) FROM schema_migrations`
	err := m.db.QueryRowContext(ctx, query).Scan(&version)
	if err != nil {
		return 0, pkgerrors.InternalError("failed to get latest version", err)
	}
	
	if !version.Valid {
		return 0, nil
	}
	
	return int(version.Int64), nil
}

// LoadMigrations loads all migration files
func (m *Migrator) LoadMigrations() ([]MigrationFile, error) {
	var migrations []MigrationFile
	
	entries, err := fs.ReadDir(migrationFiles, "sql")
	if err != nil {
		return nil, pkgerrors.InternalError("failed to read migrations directory", err)
	}
	
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		
		migration, err := m.parseMigrationFile(entry.Name())
		if err != nil {
			return nil, err
		}
		
		migrations = append(migrations, migration)
	}
	
	// Sort by version
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})
	
	return migrations, nil
}

// parseMigrationFile parses a migration file
func (m *Migrator) parseMigrationFile(filename string) (MigrationFile, error) {
	// Expected format: 001_create_tables.sql
	parts := strings.SplitN(filename, "_", 2)
	if len(parts) != 2 {
		return MigrationFile{}, pkgerrors.ValidationError(
			"invalid migration filename format: %s (expected: XXX_description.sql)", 
			filename,
		)
	}
	
	// Parse version
	var version int
	if _, err := fmt.Sscanf(parts[0], "%03d", &version); err != nil {
		return MigrationFile{}, pkgerrors.ValidationError(
			"invalid migration version in filename: %s", 
			filename,
		)
	}
	
	// Read file content
	content, err := migrationFiles.ReadFile("sql/" + filename)
	if err != nil {
		return MigrationFile{}, pkgerrors.InternalError("failed to read migration file", err).
			WithContext("filename", filename)
	}
	
	// Parse content
	upSQL, downSQL, description := parseMigrationContent(string(content))
	
	// Calculate checksum
	checksum := calculateChecksum(upSQL)
	
	// Get name from filename
	name := strings.TrimSuffix(parts[1], ".sql")
	
	return MigrationFile{
		Version:     version,
		Name:        name,
		Description: description,
		UpSQL:       upSQL,
		DownSQL:     downSQL,
		Checksum:    checksum,
	}, nil
}

// parseMigrationContent parses the migration file content
func parseMigrationContent(content string) (up, down, description string) {
	lines := strings.Split(content, "\n")
	var currentSection string
	var upLines, downLines []string
	
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Check for section markers
		if strings.HasPrefix(trimmed, "-- +migrate Up") {
			currentSection = "up"
			continue
		} else if strings.HasPrefix(trimmed, "-- +migrate Down") {
			currentSection = "down"
			continue
		} else if strings.HasPrefix(trimmed, "-- Description:") {
			description = strings.TrimSpace(strings.TrimPrefix(trimmed, "-- Description:"))
			currentSection = "" // Reset section after description
			continue
		} else if strings.HasPrefix(trimmed, "-- +migrate") {
			// Any other migrate directive stops current section
			currentSection = ""
			continue
		}
		
		// Stop adding to section if we hit another marker or empty section
		if currentSection == "" {
			continue
		}
		
		// Add line to appropriate section
		switch currentSection {
		case "up":
			upLines = append(upLines, line)
		case "down":
			downLines = append(downLines, line)
		}
	}
	
	up = strings.TrimSpace(strings.Join(upLines, "\n"))
	down = strings.TrimSpace(strings.Join(downLines, "\n"))
	
	return up, down, description
}

// Migrate runs all pending migrations
func (m *Migrator) Migrate(ctx context.Context) error {
	// Initialize migrations table
	if err := m.Initialize(ctx); err != nil {
		return err
	}
	
	// Get current version
	currentVersion, err := m.GetLatestVersion(ctx)
	if err != nil {
		return err
	}
	
	// Load all migrations
	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}
	
	// Run pending migrations
	for _, migration := range migrations {
		if migration.Version <= currentVersion {
			// Already applied, verify checksum
			if err := m.verifyChecksum(ctx, migration); err != nil {
				return err
			}
			continue
		}
		
		if err := m.runMigration(ctx, migration); err != nil {
			return pkgerrors.InternalError(
				fmt.Sprintf("failed to run migration %03d_%s", migration.Version, migration.Name), 
				err,
			)
		}
		
		fmt.Printf("Applied migration %03d: %s\n", migration.Version, migration.Name)
	}
	
	return nil
}

// Rollback rolls back the last n migrations
func (m *Migrator) Rollback(ctx context.Context, steps int) error {
	if steps <= 0 {
		return pkgerrors.ValidationError("rollback steps must be greater than 0")
	}
	
	// Get applied migrations
	applied, err := m.GetAppliedMigrations(ctx)
	if err != nil {
		return err
	}
	
	if len(applied) == 0 {
		return pkgerrors.ValidationError("no migrations to rollback")
	}
	
	// Load all migrations
	allMigrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}
	
	// Create map for quick lookup
	migrationMap := make(map[int]MigrationFile)
	for _, mig := range allMigrations {
		migrationMap[mig.Version] = mig
	}
	
	// Determine migrations to rollback
	rollbackCount := steps
	if rollbackCount > len(applied) {
		rollbackCount = len(applied)
	}
	
	// Rollback in reverse order
	for i := len(applied) - 1; i >= len(applied)-rollbackCount; i-- {
		migration := applied[i]
		migFile, ok := migrationMap[migration.Version]
		if !ok {
			return pkgerrors.InternalError(
				fmt.Sprintf("migration file not found for version %d", migration.Version),
				nil,
			)
		}
		
		if err := m.rollbackMigration(ctx, migFile); err != nil {
			return pkgerrors.InternalError(
				fmt.Sprintf("failed to rollback migration %03d_%s", migration.Version, migration.Name),
				err,
			)
		}
		
		fmt.Printf("Rolled back migration %03d: %s\n", migration.Version, migration.Name)
	}
	
	return nil
}

// runMigration runs a single migration
func (m *Migrator) runMigration(ctx context.Context, migration MigrationFile) error {
	tx, err := m.db.BeginTxx(ctx, nil)
	if err != nil {
		return pkgerrors.InternalError("failed to begin transaction", err)
	}
	defer tx.Rollback()
	
	start := time.Now()
	
	// Execute migration
	if _, err := tx.ExecContext(ctx, migration.UpSQL); err != nil {
		return pkgerrors.InternalError("failed to execute migration", err).
			WithContext("sql", migration.UpSQL)
	}
	
	// Record migration
	execTime := time.Since(start)
	id := fmt.Sprintf("%03d_%s", migration.Version, migration.Name)
	
	query := `
	INSERT INTO schema_migrations (id, version, name, description, checksum, applied_at, execution_time_ms)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	
	_, err = tx.ExecContext(ctx, query,
		id,
		migration.Version,
		migration.Name,
		migration.Description,
		migration.Checksum,
		time.Now(),
		execTime.Milliseconds(),
	)
	if err != nil {
		return pkgerrors.InternalError("failed to record migration", err)
	}
	
	return tx.Commit()
}

// rollbackMigration rolls back a single migration
func (m *Migrator) rollbackMigration(ctx context.Context, migration MigrationFile) error {
	if migration.DownSQL == "" {
		return pkgerrors.ValidationError("migration %03d has no rollback SQL", migration.Version)
	}
	
	tx, err := m.db.BeginTxx(ctx, nil)
	if err != nil {
		return pkgerrors.InternalError("failed to begin transaction", err)
	}
	defer tx.Rollback()
	
	// Execute rollback
	if _, err := tx.ExecContext(ctx, migration.DownSQL); err != nil {
		return pkgerrors.InternalError("failed to execute rollback", err).
			WithContext("sql", migration.DownSQL)
	}
	
	// Remove migration record
	query := `DELETE FROM schema_migrations WHERE version = ?`
	if _, err := tx.ExecContext(ctx, query, migration.Version); err != nil {
		return pkgerrors.InternalError("failed to remove migration record", err)
	}
	
	return tx.Commit()
}

// verifyChecksum verifies that an applied migration hasn't changed
func (m *Migrator) verifyChecksum(ctx context.Context, migration MigrationFile) error {
	var checksum string
	query := `SELECT checksum FROM schema_migrations WHERE version = ?`
	
	err := m.db.QueryRowContext(ctx, query, migration.Version).Scan(&checksum)
	if err != nil {
		return pkgerrors.InternalError("failed to get migration checksum", err).
			WithContext("version", migration.Version)
	}
	
	if checksum != migration.Checksum {
		return pkgerrors.ValidationError(
			"migration %03d checksum mismatch: migration file has been modified after being applied",
			migration.Version,
		).WithContext("expected", checksum).WithContext("actual", migration.Checksum)
	}
	
	return nil
}

// calculateChecksum calculates SHA256 checksum of migration content
func calculateChecksum(content string) string {
	hash := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", hash)
}