package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestServer constructs a Server with a nil-AuthService Dependencies struct.
// Auth-route registration is skipped in this configuration, so tests targeting
// /health, /, and (in U4) /static can run without an auth backend.
func newTestServer(cfg config.WebServerConfig) *Server {
	return NewServer(cfg, Dependencies{}, utils.NewLogger("", false))
}

func TestNewServer(t *testing.T) {
	cfg := config.WebServerConfig{
		Host: "localhost",
		Port: 8080,
	}
	logger := utils.NewLogger("", false)
	deps := Dependencies{}

	server := NewServer(cfg, deps, logger)

	assert.NotNil(t, server)
	assert.Equal(t, cfg, server.config)
	assert.Equal(t, deps, server.deps)
	assert.Equal(t, logger, server.logger)
}

func TestServer_HealthEndpoint(t *testing.T) {
	server := newTestServer(config.WebServerConfig{})

	ctx := context.Background()
	err := server.Start(ctx, "localhost", 0)
	require.NoError(t, err)
	defer func() {
		if err := server.Shutdown(ctx); err != nil {
			t.Logf("Failed to shutdown server: %v", err)
		}
	}()

	// Wait a moment for server to start
	time.Sleep(10 * time.Millisecond)

	// Test health endpoint
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestServer_RootEndpoint(t *testing.T) {
	server := newTestServer(config.WebServerConfig{})

	ctx := context.Background()
	err := server.Start(ctx, "localhost", 0)
	require.NoError(t, err)
	defer func() {
		if err := server.Shutdown(ctx); err != nil {
			t.Logf("Failed to shutdown server: %v", err)
		}
	}()

	// Wait a moment for server to start
	time.Sleep(10 * time.Millisecond)

	tests := []struct {
		name           string
		path           string
		expectedStatus int
		expectedBody   string
		containsBody   bool
	}{
		{
			name:           "root path",
			path:           "/",
			expectedStatus: http.StatusOK,
			expectedBody:   "<h1>ZeroDayBuddy</h1>",
			containsBody:   true,
		},
		{
			name:           "non-existent path",
			path:           "/nonexistent",
			expectedStatus: http.StatusNotFound,
			expectedBody:   "404 page not found",
			containsBody:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.containsBody {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			} else {
				assert.Equal(t, tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestServer_StartAndShutdown(t *testing.T) {
	server := newTestServer(config.WebServerConfig{})

	ctx := context.Background()

	// Start the server
	err := server.Start(ctx, "localhost", 0)
	require.NoError(t, err)
	assert.NotNil(t, server.server)

	// Wait a moment for server to start
	time.Sleep(10 * time.Millisecond)

	// Verify server is running by making a request
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Shutdown the server
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = server.Shutdown(shutdownCtx)
	require.NoError(t, err)
}

func TestServer_TimeoutConfiguration(t *testing.T) {
	server := newTestServer(config.WebServerConfig{})

	ctx := context.Background()
	err := server.Start(ctx, "localhost", 0)
	require.NoError(t, err)
	defer func() {
		if err := server.Shutdown(ctx); err != nil {
			t.Logf("Failed to shutdown server: %v", err)
		}
	}()

	// Check timeout configuration
	assert.Equal(t, 15*time.Second, server.server.ReadTimeout)
	assert.Equal(t, 15*time.Second, server.server.WriteTimeout)
	assert.Equal(t, 60*time.Second, server.server.IdleTimeout)
}

func TestServer_ConcurrentRequests(t *testing.T) {
	server := newTestServer(config.WebServerConfig{})

	ctx := context.Background()
	err := server.Start(ctx, "localhost", 0)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown(ctx) }()

	// Wait a moment for server to start
	time.Sleep(10 * time.Millisecond)

	// Send multiple concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			w := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			done <- true
		}()
	}

	// Wait for all requests to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestServer_CustomHostAndPort(t *testing.T) {
	server := newTestServer(config.WebServerConfig{})

	ctx := context.Background()
	err := server.Start(ctx, "127.0.0.1", 12345)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown(ctx) }()

	assert.Equal(t, "127.0.0.1:12345", server.server.Addr)
}

func TestServer_ContentTypeHeaders(t *testing.T) {
	server := newTestServer(config.WebServerConfig{})

	ctx := context.Background()
	err := server.Start(ctx, "localhost", 0)
	require.NoError(t, err)
	defer func() { _ = server.Shutdown(ctx) }()

	// Wait a moment for server to start
	time.Sleep(10 * time.Millisecond)

	// Test root endpoint returns HTML content type
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusOK, w.Code)
}
