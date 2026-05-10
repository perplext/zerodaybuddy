package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/stretchr/testify/assert"
)

// T2-3 (U2) reshaped these tests: static assets are no longer served from a
// runtime-configurable filesystem path. They live in EmbeddedFS, baked into
// the binary at compile time. Tests assert against what's actually in the
// embedded tree (currently: the .gitkeep files U2 added; future units add
// pico.min.css, htmx.min.js, etc.).

// -- Index / served at "/" --

func TestStatic_IndexServesAPIDocs(t *testing.T) {
	srv := newTestServer(config.WebServerConfig{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	// Old welcome stub from pre-T2-1 is gone.
	assert.NotContains(t, body, "Welcome to ZeroDayBuddy - the bug bounty management tool.")
	// Index lists key API endpoints.
	assert.Contains(t, body, "API server is running")
	assert.Contains(t, body, "/api/auth/login")
	assert.Contains(t, body, "/api/auth/profile")
	assert.Contains(t, body, "/health")
	// CSP-clean: no inline script or style tags.
	assert.NotContains(t, body, "<script")
	assert.NotContains(t, body, "<style")
}

// -- Static file server backed by embedded FS --

func TestStatic_FileServerServesEmbeddedGitkeep(t *testing.T) {
	// .gitkeep files were placed in embedded/static/{css,js,img}/ during U2.
	// Serving them confirms the embedded FS is wired correctly.
	srv := newTestServer(config.WebServerConfig{})

	req := httptest.NewRequest(http.MethodGet, "/static/css/.gitkeep", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "embedded .gitkeep must be served")
}

func TestStatic_DirectoryRequestReturns404(t *testing.T) {
	srv := newTestServer(config.WebServerConfig{})

	req := httptest.NewRequest(http.MethodGet, "/static/css/", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code,
		"directory requests must 404 — never expose a file listing")
}

func TestStatic_MissingFileReturns404(t *testing.T) {
	srv := newTestServer(config.WebServerConfig{})

	req := httptest.NewRequest(http.MethodGet, "/static/missing.css", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestStatic_PathTraversalBlocked(t *testing.T) {
	srv := newTestServer(config.WebServerConfig{})

	traversals := []string{
		"/static/../server.go",
		"/static/..%2fserver.go",
		"/static/../../etc/passwd",
	}
	for _, p := range traversals {
		t.Run(p, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, p, nil)
			w := httptest.NewRecorder()
			srv.buildRouter().ServeHTTP(w, req)
			// Body MUST NOT contain anything that would only exist outside
			// the embedded static root. Source content from server.go would
			// indicate a successful traversal.
			assert.NotContains(t, w.Body.String(), "package web",
				"path traversal must not expose files outside the embedded static root")
			// Status MUST NOT be 200.
			assert.NotEqual(t, http.StatusOK, w.Code,
				"path traversal must not return 200 (got %d)", w.Code)
		})
	}
}

func TestStatic_SecurityHeadersAppliedToStaticResponses(t *testing.T) {
	srv := newTestServer(config.WebServerConfig{})

	req := httptest.NewRequest(http.MethodGet, "/static/css/.gitkeep", nil)
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
}
