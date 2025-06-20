package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateMigrateCommand(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	cmd := createMigrateCommand(app)
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "migrate", cmd.Use)
	assert.Contains(t, cmd.Short, "database migrations")
	
	// Check subcommands
	subcommands := []string{"up", "down", "status", "create"}
	assert.Equal(t, len(subcommands), len(cmd.Commands()))
	
	for _, subcmd := range subcommands {
		found := false
		for _, c := range cmd.Commands() {
			if c.Use == subcmd {
				found = true
				break
			}
		}
		assert.True(t, found, "Subcommand %s should be registered", subcmd)
	}
}

func TestMigrateUpCommand(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	cmd := createMigrateUpCommand(app)
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "up", cmd.Use)
	assert.Contains(t, cmd.Short, "Apply")
	
	// Test execution would require a real database connection
	// which we skip in unit tests
}

func TestMigrateDownCommand(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	cmd := createMigrateDownCommand(app)
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "down", cmd.Use)
	assert.Contains(t, cmd.Short, "Rollback")
	
	// Test with valid steps
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--steps", "5"})
	
	// Note: Actual execution would fail without a real database
	// This just tests the command setup
	
	// Test with invalid steps
	cmd.SetArgs([]string{"--steps", "-1"})
	// Would return validation error in real execution
	
	cmd.SetArgs([]string{"--steps", "200"})
	// Would return "too many steps" error in real execution
}

func TestMigrateStatusCommand(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	cmd := createMigrateStatusCommand(app)
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "status", cmd.Use)
	assert.Contains(t, cmd.Short, "Show migration status")
}

func TestMigrateCreateCommand(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	cmd := createMigrateCreateCommand(app)
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "create", cmd.Use)
	assert.Contains(t, cmd.Short, "Create")
	
	// Test with valid name
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--name", "add_user_table"})
	
	// Note: Would create migration file in real execution
	
	// Test without name
	cmd.SetArgs([]string{})
	// Would return "migration name is required" error
}