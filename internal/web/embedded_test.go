package web

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// EmbeddedFS smoke tests — the contents are bundled into the binary, so
// these verify nothing regresses against accidental file removal or path
// renames during template/static work in U3-U6.

func TestEmbeddedFS_VendoredAssetsPresent(t *testing.T) {
	expected := []string{
		"embedded/static/js/htmx.min.js",
		"embedded/static/js/json-enc.js",
		"embedded/static/js/zdb.js",
		"embedded/static/css/pico.min.css",
		"embedded/static/css/zdb.css",
		"embedded/static/VENDORED.md",
	}
	for _, path := range expected {
		t.Run(path, func(t *testing.T) {
			f, err := EmbeddedFS.Open(path)
			require.NoError(t, err, "expected %s to be embedded", path)
			t.Cleanup(func() { _ = f.Close() })

			info, err := f.Stat()
			require.NoError(t, err)
			assert.Greater(t, info.Size(), int64(0), "%s must not be empty", path)
		})
	}
}

func TestEmbeddedFS_StaticGitkeepsPresent(t *testing.T) {
	// .gitkeep files preserve the directory structure in git for img/ which
	// has no real assets yet. Without `all:` prefix in the //go:embed
	// directive these would be missed.
	for _, path := range []string{
		"embedded/static/css/.gitkeep",
		"embedded/static/js/.gitkeep",
		"embedded/static/img/.gitkeep",
	} {
		_, err := EmbeddedFS.Open(path)
		assert.NoError(t, err, "%s must be embedded (use all: prefix)", path)
	}
}

func TestEmbeddedFS_StaticSubFSWorks(t *testing.T) {
	// fs.Sub is what server.go uses to scope http.FileServer to the static
	// subtree. Verify it returns a usable filesystem with the expected layout.
	staticFS, err := fs.Sub(EmbeddedFS, "embedded/static")
	require.NoError(t, err)

	f, err := staticFS.Open("js/htmx.min.js")
	require.NoError(t, err, "fs.Sub must scope correctly so /js/htmx.min.js resolves")
	defer func() { _ = f.Close() }()
}

func TestEmbeddedFS_PicoCSSContentLooksRight(t *testing.T) {
	// Sanity check that pico.min.css is actually CSS and not some random
	// file accidentally placed at this path.
	data, err := fs.ReadFile(EmbeddedFS, "embedded/static/css/pico.min.css")
	require.NoError(t, err)
	body := string(data)
	assert.True(t, strings.Contains(body, "html") || strings.Contains(body, ":root"),
		"pico.min.css must contain typical CSS selectors")
}
