package migrations

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateWithEmbeddedFiles(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	
	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize migrations table
	err := migrator.Initialize(ctx)
	require.NoError(t, err)

	// Run migrations - this will use the embedded SQL files
	err = migrator.Migrate(ctx)
	require.NoError(t, err)

	// Check that migrations were applied
	migrations, err := migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, migrations)

	// Check latest version
	version, err := migrator.GetLatestVersion(ctx)
	require.NoError(t, err)
	assert.Greater(t, version, 0)

	// Running migrate again should be idempotent
	err = migrator.Migrate(ctx)
	require.NoError(t, err)

	// Same number of migrations should be applied
	migrations2, err := migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Len(t, migrations2, len(migrations))
}

func TestLoadMigrationsFromEmbedded(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	
	migrator := NewMigrator(db)

	// Load migrations from embedded files
	files, err := migrator.LoadMigrations()
	require.NoError(t, err)
	assert.NotEmpty(t, files)

	// Check that migrations have required fields
	for _, file := range files {
		assert.Greater(t, file.Version, 0)
		assert.NotEmpty(t, file.Name)
		assert.NotEmpty(t, file.UpSQL)
		assert.NotEmpty(t, file.DownSQL)
		assert.NotEmpty(t, file.Checksum)
	}
}

func TestRollbackWithSteps(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	
	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize and apply migrations
	err := migrator.Initialize(ctx)
	require.NoError(t, err)
	
	err = migrator.Migrate(ctx)
	require.NoError(t, err)

	// Get initial migration count
	migrations, err := migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	initialCount := len(migrations)
	
	if initialCount == 0 {
		t.Skip("No migrations to rollback")
	}

	// Rollback 1 step
	err = migrator.Rollback(ctx, 1)
	require.NoError(t, err)

	// Check that one migration was rolled back
	migrations, err = migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Len(t, migrations, initialCount-1)

	// Test rollback with invalid steps
	err = migrator.Rollback(ctx, -1)
	assert.Error(t, err)

	// If there are no migrations left, rollback should error
	if len(migrations) == 0 {
		err = migrator.Rollback(ctx, 1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no migrations to rollback")
	}
}

func TestRunAndRollbackMigration(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	
	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize
	err := migrator.Initialize(ctx)
	require.NoError(t, err)

	// Create a test migration
	testMigration := MigrationFile{
		Version:     999,
		Name:        "test",
		Description: "Test migration",
		UpSQL:       "CREATE TABLE test_run (id INTEGER PRIMARY KEY);",
		DownSQL:     "DROP TABLE test_run;",
		Checksum:    calculateChecksum("CREATE TABLE test_run (id INTEGER PRIMARY KEY);"),
	}

	// Run the migration
	start := time.Now()
	err = migrator.runMigration(ctx, testMigration)
	require.NoError(t, err)

	// Verify table was created
	var tableExists bool
	err = db.Get(&tableExists, `
		SELECT EXISTS(
			SELECT 1 FROM sqlite_master 
			WHERE type='table' AND name='test_run'
		)
	`)
	require.NoError(t, err)
	assert.True(t, tableExists)

	// Verify migration was recorded
	applied, err := migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	
	var found bool
	for _, m := range applied {
		if m.Version == 999 {
			found = true
			assert.Equal(t, testMigration.Name, m.Name)
			assert.Equal(t, testMigration.Description, m.Description)
			assert.Equal(t, testMigration.Checksum, m.Checksum)
			assert.True(t, m.AppliedAt.After(start))
			assert.GreaterOrEqual(t, m.ExecutionTime, time.Duration(0))
			break
		}
	}
	assert.True(t, found, "Migration should be recorded")

	// Now rollback
	err = migrator.rollbackMigration(ctx, testMigration)
	require.NoError(t, err)

	// Verify table was dropped
	err = db.Get(&tableExists, `
		SELECT EXISTS(
			SELECT 1 FROM sqlite_master 
			WHERE type='table' AND name='test_run'
		)
	`)
	require.NoError(t, err)
	assert.False(t, tableExists)

	// Verify migration was removed
	applied, err = migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	
	found = false
	for _, m := range applied {
		if m.Version == 999 {
			found = true
			break
		}
	}
	assert.False(t, found, "Migration should be removed")
}

func TestVerifyChecksum(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()
	
	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize
	err := migrator.Initialize(ctx)
	require.NoError(t, err)

	// Create and apply a test migration
	migration := MigrationFile{
		Version:     999,
		Name:        "checksum_test",
		Description: "Checksum test",
		UpSQL:       "CREATE TABLE checksum_test (id INTEGER);",
		DownSQL:     "DROP TABLE checksum_test;",
		Checksum:    calculateChecksum("CREATE TABLE checksum_test (id INTEGER);"),
	}

	err = migrator.runMigration(ctx, migration)
	require.NoError(t, err)

	// Verify with correct checksum should pass
	err = migrator.verifyChecksum(ctx, migration)
	require.NoError(t, err)

	// Verify with incorrect checksum should fail
	migrationWrong := migration
	migrationWrong.Checksum = "wrong-checksum"
	err = migrator.verifyChecksum(ctx, migrationWrong)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")

	// Verify non-existent migration should fail
	migrationNonExistent := MigrationFile{
		Version:  99999,
		Checksum: "any-checksum",
	}
	err = migrator.verifyChecksum(ctx, migrationNonExistent)
	assert.Error(t, err)

	// Clean up
	migrator.rollbackMigration(ctx, migration)
}

func TestParseMigrationContent_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantUp      string
		wantDown    string
		wantDesc    string
	}{
		{
			name: "Multiple descriptions",
			content: `-- Description: First description
-- Description: Second description

-- +migrate Up
CREATE TABLE test;

-- +migrate Down
DROP TABLE test;`,
			wantUp:   "CREATE TABLE test;",
			wantDown: "DROP TABLE test;",
			wantDesc: "Second description", // Last one wins
		},
		{
			name: "Comments in SQL",
			content: `-- Description: Test

-- +migrate Up
-- This is a comment
CREATE TABLE test; -- inline comment

-- +migrate Down
DROP TABLE test;`,
			wantUp:   "-- This is a comment\nCREATE TABLE test; -- inline comment",
			wantDown: "DROP TABLE test;",
			wantDesc: "Test",
		},
		{
			name: "Empty sections",
			content: `-- +migrate Up

-- +migrate Down

`,
			wantUp:   "",
			wantDown: "",
			wantDesc: "",
		},
		{
			name: "No end marker",
			content: `-- Description: No end

-- +migrate Up
CREATE TABLE test;

-- +migrate Down
DROP TABLE test;

Some extra content here`,
			wantUp:   "CREATE TABLE test;",
			wantDown: "DROP TABLE test;\n\nSome extra content here",
			wantDesc: "No end",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up, down, desc := parseMigrationContent(tt.content)
			assert.Equal(t, tt.wantUp, up)
			assert.Equal(t, tt.wantDown, down)
			assert.Equal(t, tt.wantDesc, desc)
		})
	}
}