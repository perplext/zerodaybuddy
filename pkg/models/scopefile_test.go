package models

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeTemp writes content to a temp file with the given name and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

const validYAML = `
in_scope:
  - type: domain
    value: example.com
  - type: domain
    value: "*.example.com"
  - type: ip
    value: 10.0.0.0/8
  - type: url
    value: https://app.example.com/api
out_of_scope:
  - type: domain
    value: blog.example.com
`

const validJSON = `{
  "in_scope": [
    {"type": "domain", "value": "example.com"},
    {"type": "domain", "value": "*.example.com"},
    {"type": "ip", "value": "10.0.0.0/8"},
    {"type": "url", "value": "https://app.example.com/api"}
  ],
  "out_of_scope": [
    {"type": "domain", "value": "blog.example.com"}
  ]
}`

// TestLoadScopeFile_YAMLHappyPath specifically guards the yaml-struct-tag bug:
// without yaml tags on Scope/Asset, in_scope unmarshals to an empty slice.
func TestLoadScopeFile_YAMLHappyPath(t *testing.T) {
	scope, err := LoadScopeFile(writeTemp(t, "scope.yaml", validYAML))
	require.NoError(t, err)
	require.NotNil(t, scope)

	assert.Len(t, scope.InScope, 4, "yaml in_scope must not parse to empty (yaml tags present)")
	assert.Len(t, scope.OutOfScope, 1)

	// IsInScope must agree on a wildcard subdomain and an in-CIDR IP.
	assert.True(t, scope.IsInScope(AssetTypeDomain, "api.example.com"), "wildcard subdomain in scope")
	assert.True(t, scope.IsInScope(AssetTypeIP, "10.1.2.3"), "in-CIDR IP in scope")
	assert.False(t, scope.IsInScope(AssetTypeDomain, "blog.example.com"), "out-of-scope domain excluded")
}

func TestLoadScopeFile_JSONMatchesYAML(t *testing.T) {
	yamlScope, err := LoadScopeFile(writeTemp(t, "scope.yaml", validYAML))
	require.NoError(t, err)
	jsonScope, err := LoadScopeFile(writeTemp(t, "scope.json", validJSON))
	require.NoError(t, err)

	assert.Equal(t, len(yamlScope.InScope), len(jsonScope.InScope))
	assert.Equal(t, len(yamlScope.OutOfScope), len(jsonScope.OutOfScope))
}

func TestLoadScopeFile_ExtensionlessParsesAsYAML(t *testing.T) {
	scope, err := LoadScopeFile(writeTemp(t, "scopefile", validYAML))
	require.NoError(t, err)
	assert.Len(t, scope.InScope, 4)
}

func TestLoadScopeFile_EmptyOutOfScopeAllowed(t *testing.T) {
	scope, err := LoadScopeFile(writeTemp(t, "s.yaml", "in_scope:\n  - type: domain\n    value: example.com\n"))
	require.NoError(t, err)
	assert.Len(t, scope.InScope, 1)
	assert.Empty(t, scope.OutOfScope)
}

func TestLoadScopeFile_MissingInScopeRejected(t *testing.T) {
	_, err := LoadScopeFile(writeTemp(t, "s.yaml", "out_of_scope:\n  - type: domain\n    value: example.com\n"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScopeNoInScope)
}

func TestLoadScopeFile_UnknownAssetTypeRejected(t *testing.T) {
	_, err := LoadScopeFile(writeTemp(t, "s.yaml", "in_scope:\n  - type: web\n    value: example.com\n"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScopeInvalidType)
	assert.Contains(t, err.Error(), "web", "error should name the offending value")
}

func TestLoadScopeFile_UnknownKeyRejected(t *testing.T) {
	// "in_scopes" (typo) must error via strict decode, not silently yield empty scope.
	_, err := LoadScopeFile(writeTemp(t, "s.yaml", "in_scopes:\n  - type: domain\n    value: example.com\n"))
	require.Error(t, err)
}

func TestLoadScopeFile_EmptyValueRejected(t *testing.T) {
	_, err := LoadScopeFile(writeTemp(t, "s.yaml", "in_scope:\n  - type: domain\n    value: \"\"\n"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScopeEmptyValue)
}

func TestLoadScopeFile_OversizeRejected(t *testing.T) {
	big := "in_scope:\n" + strings.Repeat("  - type: domain\n    value: example.com\n", 60000)
	_, err := LoadScopeFile(writeTemp(t, "s.yaml", big))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScopeFileTooLarge)
}

func TestLoadScopeFile_MalformedYAMLNoPanic(t *testing.T) {
	_, err := LoadScopeFile(writeTemp(t, "s.yaml", "in_scope: [ this is : not valid yaml"))
	require.Error(t, err)
}

func TestLoadScopeFile_MissingFile(t *testing.T) {
	_, err := LoadScopeFile(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.Error(t, err)
}

func TestLoadScopeFile_EmptyFile(t *testing.T) {
	_, err := LoadScopeFile(writeTemp(t, "s.yaml", "   \n"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrScopeFileEmpty)
}

func TestValidateScope_TrimsAssetValues(t *testing.T) {
	// Surrounding whitespace must be trimmed in place so later IsInScope
	// matching (which compares the stored value) succeeds.
	s := &Scope{InScope: []Asset{{Type: AssetTypeDomain, Value: "  example.com  "}}}
	require.NoError(t, ValidateScope(s))
	assert.Equal(t, "example.com", s.InScope[0].Value, "value should be trimmed in place")
	assert.True(t, s.IsInScope(AssetTypeDomain, "example.com"))
}

func TestValidateScope_NilAndDirect(t *testing.T) {
	assert.ErrorIs(t, ValidateScope(nil), ErrScopeNoInScope)

	good := &Scope{InScope: []Asset{{Type: AssetTypeDomain, Value: "example.com"}}}
	assert.NoError(t, ValidateScope(good))
}

func TestIsValidAssetType(t *testing.T) {
	assert.True(t, IsValidAssetType(AssetTypeSmartContract))
	assert.True(t, IsValidAssetType(AssetTypeRepository))
	assert.False(t, IsValidAssetType(AssetType("web")))
	assert.False(t, IsValidAssetType(AssetType("")))
}

// TestExampleScopeFiles ensures the shipped examples stay valid.
func TestExampleScopeFiles(t *testing.T) {
	for _, f := range []string{"../../examples/scope.yaml", "../../examples/scope.json"} {
		t.Run(f, func(t *testing.T) {
			if _, err := os.Stat(f); errors.Is(err, os.ErrNotExist) {
				t.Skipf("example file %s not present", f)
			}
			scope, err := LoadScopeFile(f)
			require.NoError(t, err)
			assert.NotEmpty(t, scope.InScope)
		})
	}
}
