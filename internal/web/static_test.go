package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newServerWithStatic builds a Server rooted at a temp dir with the given
// static-asset layout. Returns the server and the temp dir path so tests
// can assert on file contents.
func newServerWithStatic(t *testing.T, files map[string]string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	for relPath, content := range files {
		full := filepath.Join(dir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}
	srv := NewServer(
		config.WebServerConfig{},
		Dependencies{StaticDir: dir},
		utils.NewLogger("", false),
	)
	return srv, dir
}

// -- Index API documentation --

func TestStatic_IndexServesAPIDocs(t *testing.T) {
	srv := newTestServer(config.WebServerConfig{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Old welcome stub is gone
	assert.NotContains(t, body, "Welcome to ZeroDayBuddy - the bug bounty management tool.")
	// New index lists key API endpoints
	assert.Contains(t, body, "API server is running")
	assert.Contains(t, body, "/api/auth/login")
	assert.Contains(t, body, "/api/auth/profile")
	assert.Contains(t, body, "/health")
	// CSP-clean: no inline script or style tags
	assert.NotContains(t, body, "<script")
	assert.NotContains(t, body, "<style")
}

// -- Static file server happy path --

func TestStatic_FileServerServesExistingFile(t *testing.T) {
	srv, _ := newServerWithStatic(t, map[string]string{
		"css/app.css": "body { color: red; }",
	})

	req := httptest.NewRequest(http.MethodGet, "/static/css/app.css", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "body { color: red; }", w.Body.String())
}

func TestStatic_FileServerEmptyFileServesOK(t *testing.T) {
	// Mirrors what the .gitkeep files look like — empty file, should still 200.
	srv, _ := newServerWithStatic(t, map[string]string{
		"css/.gitkeep": "",
	})

	req := httptest.NewRequest(http.MethodGet, "/static/css/.gitkeep", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// -- Static file server: not registered when StaticDir empty --

func TestStatic_NotRegisteredWhenStaticDirEmpty(t *testing.T) {
	srv := NewServer(config.WebServerConfig{}, Dependencies{}, utils.NewLogger("", false))

	req := httptest.NewRequest(http.MethodGet, "/static/anything", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// -- Directory listing suppression --

func TestStatic_DirectoryRequestReturns404(t *testing.T) {
	srv, _ := newServerWithStatic(t, map[string]string{
		"css/app.css": "body { color: red; }",
	})

	req := httptest.NewRequest(http.MethodGet, "/static/css/", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code,
		"directory requests must 404, never expose a file listing")
}

func TestStatic_DirectoryWithIndexHTMLServesIndex(t *testing.T) {
	srv, _ := newServerWithStatic(t, map[string]string{
		"index.html": "<p>welcome</p>",
	})

	// http.FileServer auto-redirects "/static" -> "/static/" when there's no file.
	// Request the trailing-slash form directly, which then resolves to index.html.
	req := httptest.NewRequest(http.MethodGet, "/static/", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "welcome")
}

// -- Non-existent file --

func TestStatic_MissingFileReturns404(t *testing.T) {
	srv, _ := newServerWithStatic(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/static/missing.css", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// -- Path traversal blocked by http.FileServer's built-in path cleaning --

func TestStatic_PathTraversalBlocked(t *testing.T) {
	srv, dir := newServerWithStatic(t, map[string]string{
		"app.css": "ok",
	})

	// Create a sensitive file OUTSIDE the static root, alongside it
	parent := filepath.Dir(dir)
	secret := filepath.Join(parent, "secret.txt")
	require.NoError(t, os.WriteFile(secret, []byte("LEAKED"), 0o644))
	defer os.Remove(secret)

	// Try several traversal forms; all should fail to escape the static root
	traversals := []string{
		"/static/../secret.txt",
		"/static/..%2fsecret.txt",
		"/static/../../etc/passwd",
	}
	for _, p := range traversals {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			w := httptest.NewRecorder()
			srv.buildRouter().ServeHTTP(w, req)
			assert.NotContains(t, w.Body.String(), "LEAKED",
				"path traversal must not expose files outside StaticDir")
		})
	}
}

// -- Security headers on static responses --

func TestStatic_SecurityHeadersAppliedToStaticResponses(t *testing.T) {
	srv, _ := newServerWithStatic(t, map[string]string{
		"css/app.css": "body { color: red; }",
	})

	req := httptest.NewRequest(http.MethodGet, "/static/css/app.css", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
}
