package migrations

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) (*sqlx.DB, func()) {
	// Create temporary database
	tmpfile, err := os.CreateTemp("", "test-*.db")
	require.NoError(t, err)
	tmpfile.Close()

	db, err := sqlx.Connect("sqlite3", tmpfile.Name())
	require.NoError(t, err)

	cleanup := func() {
		db.Close()
		os.Remove(tmpfile.Name())
	}

	return db, cleanup
}

func TestMigratorInitialize(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize should create migrations table
	err := migrator.Initialize(ctx)
	require.NoError(t, err)

	// Check table exists
	var count int
	err = db.Get(&count, `
		SELECT COUNT(*) FROM sqlite_master 
		WHERE type='table' AND name='schema_migrations'
	`)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Initialize again should not error
	err = migrator.Initialize(ctx)
	require.NoError(t, err)
}

func TestGetLatestVersion(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize
	err := migrator.Initialize(ctx)
	require.NoError(t, err)

	// No migrations yet
	version, err := migrator.GetLatestVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, version)

	// Add a migration
	_, err = db.Exec(`
		INSERT INTO schema_migrations 
		(id, version, name, description, checksum, applied_at, execution_time_ms)
		VALUES ('001_test', 1, 'test', 'Test migration', 'abc123', ?, 100)
	`, time.Now())
	require.NoError(t, err)

	// Should return 1
	version, err = migrator.GetLatestVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, version)

	// Add another migration
	_, err = db.Exec(`
		INSERT INTO schema_migrations 
		(id, version, name, description, checksum, applied_at, execution_time_ms)
		VALUES ('002_test2', 2, 'test2', 'Test migration 2', 'def456', ?, 200)
	`, time.Now())
	require.NoError(t, err)

	// Should return 2
	version, err = migrator.GetLatestVersion(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, version)
}

func TestGetAppliedMigrations(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	migrator := NewMigrator(db)

	// Initialize
	err := migrator.Initialize(ctx)
	require.NoError(t, err)

	// No migrations yet
	migrations, err := migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Len(t, migrations, 0)

	// Add migrations
	now := time.Now()
	_, err = db.Exec(`
		INSERT INTO schema_migrations 
		(id, version, name, description, checksum, applied_at, execution_time_ms)
		VALUES 
		('001_test', 1, 'test', 'Test migration', 'abc123', ?, 100),
		('002_test2', 2, 'test2', 'Test migration 2', 'def456', ?, 200)
	`, now, now.Add(time.Minute))
	require.NoError(t, err)

	// Should return 2 migrations in order
	migrations, err = migrator.GetAppliedMigrations(ctx)
	require.NoError(t, err)
	assert.Len(t, migrations, 2)
	assert.Equal(t, 1, migrations[0].Version)
	assert.Equal(t, 2, migrations[1].Version)
	assert.Equal(t, "test", migrations[0].Name)
	assert.Equal(t, "test2", migrations[1].Name)
	assert.Equal(t, 100*time.Millisecond, migrations[0].ExecutionTime)
	assert.Equal(t, 200*time.Millisecond, migrations[1].ExecutionTime)
}

func TestParseMigrationContent(t *testing.T) {
	content := `-- Description: Test migration

Some random content that should be ignored

-- +migrate Up
CREATE TABLE test (
    id INTEGER PRIMARY KEY
);

-- +migrate Down
DROP TABLE test;

-- +migrate End
More content to ignore
`

	up, down, description := parseMigrationContent(content)
	
	assert.Equal(t, "Test migration", description)
	assert.Equal(t, "CREATE TABLE test (\n    id INTEGER PRIMARY KEY\n);", up)
	assert.Equal(t, "DROP TABLE test;", down)
}

func TestCalculateChecksum(t *testing.T) {
	content := "CREATE TABLE test (id INTEGER PRIMARY KEY);"
	checksum1 := calculateChecksum(content)
	checksum2 := calculateChecksum(content)
	
	// Same content should produce same checksum
	assert.Equal(t, checksum1, checksum2)
	
	// Different content should produce different checksum
	content2 := "CREATE TABLE test2 (id INTEGER PRIMARY KEY);"
	checksum3 := calculateChecksum(content2)
	assert.NotEqual(t, checksum1, checksum3)
	
	// Checksum should be hex string
	assert.Regexp(t, "^[a-f0-9]{64}$", checksum1)
}