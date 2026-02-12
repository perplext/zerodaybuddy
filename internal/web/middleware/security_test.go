package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestSecurityHeaders(t *testing.T) {
	logger := utils.NewLogger("", false)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := SecurityHeaders(logger)
	wrapped := mw(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	wrapped.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "0", w.Header().Get("X-XSS-Protection"))
	assert.Equal(t, "strict-origin-when-cross-origin", w.Header().Get("Referrer-Policy"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
	assert.Contains(t, w.Header().Get("Permissions-Policy"), "camera=()")
}

func TestCORS(t *testing.T) {
	logger := utils.NewLogger("", false)
	allowedOrigins := []string{"https://example.com", "https://app.example.com"}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	mw := CORS(allowedOrigins, logger)
	wrapped := mw(handler)

	t.Run("allowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	})

	t.Run("disallowed origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		req.Header.Set("Origin", "https://evil.com")
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("no origin header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("preflight request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/api/data", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
		assert.Equal(t, "https://example.com", w.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestMaxBodySize(t *testing.T) {
	logger := utils.NewLogger("", false)
	maxBytes := int64(100)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := MaxBodySize(maxBytes, logger)
	wrapped := mw(handler)

	t.Run("small body passes", func(t *testing.T) {
		body := strings.NewReader("small")
		req := httptest.NewRequest(http.MethodPost, "/api/data", body)
		req.ContentLength = int64(len("small"))
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("oversized content-length rejected", func(t *testing.T) {
		body := strings.NewReader("x")
		req := httptest.NewRequest(http.MethodPost, "/api/data", body)
		req.ContentLength = 200 // exceeds maxBytes
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, req)

		assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	})
}
