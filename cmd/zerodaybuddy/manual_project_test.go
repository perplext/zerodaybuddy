package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testScopeYAML = `
in_scope:
  - type: domain
    value: example.com
  - type: domain
    value: "*.example.com"
out_of_scope:
  - type: domain
    value: blog.example.com
`

func writeScope(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestManualCreate_HappyPath(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	require.NoError(t, app.Initialize(context.Background()))

	scopePath := writeScope(t, "scope.yaml", testScopeYAML)

	cmd := createProjectCreateCommand(app)
	cmd.SetArgs([]string{"--manual", "--name", "manual-target", "--scope-file", scopePath})
	require.NoError(t, cmd.Execute())

	project, err := app.GetStore().GetProjectByName(context.Background(), "manual-target")
	require.NoError(t, err)
	assert.Equal(t, "manual", project.Platform)
	assert.Equal(t, "research", string(project.Type))
	assert.Len(t, project.Scope.InScope, 2)
}

func TestManualCreate_PlatformManualAlias(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	require.NoError(t, app.Initialize(context.Background()))

	scopePath := writeScope(t, "scope.json", `{"in_scope":[{"type":"domain","value":"example.com"}]}`)

	cmd := createProjectCreateCommand(app)
	// --platform manual should behave the same as --manual.
	cmd.SetArgs([]string{"--platform", "manual", "--name", "via-platform", "--scope-file", scopePath})
	require.NoError(t, cmd.Execute())

	_, err := app.GetStore().GetProjectByName(context.Background(), "via-platform")
	require.NoError(t, err)
}

func TestManualCreate_MissingScopeFile(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	require.NoError(t, app.Initialize(context.Background()))

	cmd := createProjectCreateCommand(app)
	cmd.SetArgs([]string{"--manual", "--name", "no-scope"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scope-file")
}

func TestManualCreate_MissingName(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	require.NoError(t, app.Initialize(context.Background()))

	scopePath := writeScope(t, "scope.yaml", testScopeYAML)
	cmd := createProjectCreateCommand(app)
	cmd.SetArgs([]string{"--manual", "--scope-file", scopePath})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")
}

func TestManualCreate_DisallowedExtension(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	require.NoError(t, app.Initialize(context.Background()))

	// A .txt file is rejected by the extension allowlist even though it exists.
	badPath := writeScope(t, "scope.txt", testScopeYAML)
	cmd := createProjectCreateCommand(app)
	cmd.SetArgs([]string{"--manual", "--name", "bad-ext", "--scope-file", badPath})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extension")
}

func TestManualCreate_PathTraversalRejected(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	require.NoError(t, app.Initialize(context.Background()))

	cmd := createProjectCreateCommand(app)
	cmd.SetArgs([]string{"--manual", "--name", "traversal", "--scope-file", "../../etc/passwd.yaml"})
	err := cmd.Execute()
	require.Error(t, err)
}

// Regression: the existing platform branch must still validate as before.
func TestPlatformCreate_InvalidPlatformStillErrors(t *testing.T) {
	app, cleanup := createTestApp(t)
	defer cleanup()
	require.NoError(t, app.Initialize(context.Background()))

	cmd := createProjectCreateCommand(app)
	cmd.SetArgs([]string{"--platform", "unknown", "--program", "acme"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "platform")
}
