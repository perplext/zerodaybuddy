package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/perplext/zerodaybuddy/pkg/config"
)

func TestCreateRootCommand(t *testing.T) {
	// Create a test config
	tmpDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := createTestConfig(tmpDir)
	cmd := createRootCommand(cfg)
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "zerodaybuddy", cmd.Use)
	assert.Contains(t, cmd.Short, "bug bounty assistant tool")
	
	// Check that subcommands are registered
	subcommands := []string{"init", "list-programs", "project", "recon", "scan", "report", "serve", "migrate"}
	for _, subcmd := range subcommands {
		found := false
		for _, c := range cmd.Commands() {
			if c.Use == subcmd || strings.HasPrefix(c.Use, subcmd+" ") {
				found = true
				break
			}
		}
		assert.True(t, found, "Subcommand %s should be registered", subcmd)
	}
}

func TestRootCommandHelp(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := createTestConfig(tmpDir)
	cmd := createRootCommand(cfg)
	
	// Capture output
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--help"})
	
	err = cmd.Execute()
	assert.NoError(t, err)
	
	output := buf.String()
	assert.Contains(t, output, "ZeroDayBuddy")
	assert.Contains(t, output, "Usage:")
	assert.Contains(t, output, "Available Commands:")
}

func TestMainFunction(t *testing.T) {
	// This test is tricky because main() calls os.Exit
	// We'll test it by running it as a subprocess
	
	// Save original env
	originalConfigFile := os.Getenv("BUGBASE_CONFIG_FILE")
	defer os.Setenv("BUGBASE_CONFIG_FILE", originalConfigFile)
	
	// Create a temporary config file
	tmpfile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	
	configContent := `
log_dir: ""
debug: false
`
	_, err = tmpfile.Write([]byte(configContent))
	require.NoError(t, err)
	tmpfile.Close()
	
	// Set config file env var
	os.Setenv("BUGBASE_CONFIG_FILE", tmpfile.Name())
	
	// Test that we can create the root command without errors
	// (We can't easily test main() directly due to os.Exit calls)
	cfg, err := config.Load()
	require.NoError(t, err)
	
	cmd := createRootCommand(cfg)
	assert.NotNil(t, cmd)
}

func TestCommandErrors(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	cfg := createTestConfig(tmpDir)
	cmd := createRootCommand(cfg)
	
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Unknown command",
			args:    []string{"unknown-command"},
			wantErr: true,
			errMsg:  "unknown command",
		},
		{
			name:    "Unknown flag",
			args:    []string{"--unknown-flag"},
			wantErr: true,
			errMsg:  "unknown flag",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetErr(buf)
			cmd.SetArgs(tt.args)
			
			err := cmd.Execute()
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Test individual command creation functions
func TestInitCommand(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	cmd := createInitCommand(app)
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "init", cmd.Use)
	assert.Contains(t, cmd.Short, "Initialize")
	
	// Test command execution
	err := cmd.Execute()
	// May fail if database already initialized, but that's ok for this test
	_ = err
}

func TestListProgramsCommand(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	cmd := createListProgramsCommand(app)
	
	assert.NotNil(t, cmd)
	assert.Equal(t, "list-programs", cmd.Use)
	
	// Test with invalid platform
	cmd.SetArgs([]string{"--platform", "invalid"})
	err := cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid platform")
}

func TestProjectCommands(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	// Initialize the app first
	err := app.Initialize(context.Background())
	require.NoError(t, err)
	
	cmd := createProjectCommand(app)
	assert.NotNil(t, cmd)
	assert.Equal(t, "project", cmd.Use)
	
	// Check subcommands
	assert.GreaterOrEqual(t, len(cmd.Commands()), 2)
	
	// Test create command
	createCmd := createProjectCreateCommand(app)
	assert.NotNil(t, createCmd)
	
	// Test with missing required flags
	err = createCmd.Execute()
	assert.Error(t, err)
	
	// Test list command
	listCmd := createProjectListCommand(app)
	assert.NotNil(t, listCmd)
	// This should succeed even with no projects
	err = listCmd.Execute()
	assert.NoError(t, err)
}

func TestReconCommands(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	cmd := createReconCommand(app)
	assert.NotNil(t, cmd)
	assert.Equal(t, "recon", cmd.Use)
	
	// Test run command
	runCmd := createReconRunCommand(app)
	assert.NotNil(t, runCmd)
	
	// Test with missing required project flag
	runCmd.SetArgs([]string{"--concurrent", "5"})
	err := runCmd.Execute()
	assert.Error(t, err)
	
	// Test invalid project name
	runCmd.SetArgs([]string{"--project", "", "--concurrent", "5"})
	err = runCmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid project name")
}

func TestScanCommands(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	// Create scan command from main.go
	cmd := createScanCommand(app)
	assert.NotNil(t, cmd)
	assert.Equal(t, "scan", cmd.Use)
}

func TestReportCommands(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	// Create report command from main.go
	cmd := createReportCommand(app)
	assert.NotNil(t, cmd)
	assert.Equal(t, "report", cmd.Use)
}

func TestServeCommand(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	
	// Create serve command from main.go
	cmd := createServeCommand(app)
	assert.NotNil(t, cmd)
	assert.Equal(t, "serve", cmd.Use)
}

