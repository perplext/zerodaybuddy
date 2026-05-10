package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// T2-3 (U1) tests — cookie-OR-header support in AuthMiddleware and OptionalAuth.

// -- tokenFromRequest unit tests --

func TestTokenFromRequest_HeaderOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer the-token")

	tok, ok := tokenFromRequest(r)

	assert.True(t, ok)
	assert.Equal(t, "the-token", tok)
}

func TestTokenFromRequest_CookieOnly(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "the-cookie-token"})

	tok, ok := tokenFromRequest(r)

	assert.True(t, ok)
	assert.Equal(t, "the-cookie-token", tok)
}

func TestTokenFromRequest_HeaderTakesPrecedence(t *testing.T) {
	// Both header and cookie present with different tokens. The header wins.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer header-token")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "cookie-token"})

	tok, ok := tokenFromRequest(r)

	assert.True(t, ok)
	assert.Equal(t, "header-token", tok,
		"when both header and cookie are present, the Authorization header must take precedence")
}

func TestTokenFromRequest_MalformedHeaderFallsThroughToCookie(t *testing.T) {
	// Malformed header (no "Bearer " prefix) should not block the cookie path.
	// Mixed-transport scenario: a browser with a stale extension-injected header
	// AND a valid login cookie. Pre-T2-3 behavior would have rejected on the
	// header alone; new behavior falls through.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "valid-cookie-token"})

	tok, ok := tokenFromRequest(r)

	assert.True(t, ok)
	assert.Equal(t, "valid-cookie-token", tok)
}

func TestTokenFromRequest_NoHeaderNoCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)

	_, ok := tokenFromRequest(r)

	assert.False(t, ok)
}

func TestTokenFromRequest_EmptyBearerToken(t *testing.T) {
	// "Bearer " with no token after — treat as missing.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set("Authorization", "Bearer ")

	_, ok := tokenFromRequest(r)

	assert.False(t, ok, "empty bearer token must be treated as no token")
}

func TestTokenFromRequest_EmptyCookieValue(t *testing.T) {
	// Cookie present but empty value — treat as missing.
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: ""})

	_, ok := tokenFromRequest(r)

	assert.False(t, ok, "empty cookie value must be treated as no token")
}

// -- AuthMiddleware cookie integration --

func TestAuthMiddleware_AcceptsValidCookie(t *testing.T) {
	logger := utils.NewLogger("", false)
	mockAuth := &MockAuthService{}
	user := &auth.User{ID: "u1", Username: "alice", Role: auth.RoleUser, Status: auth.StatusActive}
	mockAuth.On("ValidateToken", mock.Anything, "valid-cookie-jwt").Return(user, nil)

	var captured *auth.User
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "valid-cookie-jwt"})
	w := httptest.NewRecorder()

	AuthMiddleware(mockAuth, logger)(handler).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, user, captured)
	mockAuth.AssertExpectations(t)
}

func TestAuthMiddleware_RejectsInvalidCookie(t *testing.T) {
	logger := utils.NewLogger("", false)
	mockAuth := &MockAuthService{}
	mockAuth.On("ValidateToken", mock.Anything, "bad-cookie-jwt").Return(nil, errExpired)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run when cookie is invalid")
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "bad-cookie-jwt"})
	w := httptest.NewRecorder()

	AuthMiddleware(mockAuth, logger)(handler).ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired token")
}

// -- OptionalAuth cookie integration --

func TestOptionalAuth_AcceptsValidCookie(t *testing.T) {
	logger := utils.NewLogger("", false)
	mockAuth := &MockAuthService{}
	user := &auth.User{ID: "u1", Username: "alice", Role: auth.RoleUser, Status: auth.StatusActive}
	mockAuth.On("ValidateToken", mock.Anything, "valid-cookie").Return(user, nil)

	var captured *auth.User
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "valid-cookie"})
	w := httptest.NewRecorder()

	OptionalAuth(mockAuth, logger)(handler).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, user, captured, "OptionalAuth must populate user when cookie validates")
}

func TestOptionalAuth_PassesThroughOnInvalidCookie(t *testing.T) {
	logger := utils.NewLogger("", false)
	mockAuth := &MockAuthService{}
	mockAuth.On("ValidateToken", mock.Anything, "bad").Return(nil, errExpired)

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		assert.Nil(t, GetUserFromContext(r.Context()),
			"OptionalAuth must pass through with nil user when cookie is invalid")
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "bad"})
	w := httptest.NewRecorder()

	OptionalAuth(mockAuth, logger)(handler).ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

// -- End-to-end JWT roundtrip via cookie --

// errExpired is a sentinel for the mock to return a typed-ish error for invalid tokens.
var errExpired = mockErr("token expired")

type mockErr string

func (e mockErr) Error() string { return string(e) }

// TestAuthMiddleware_RealJWTRoundtripViaCookie sets a real auth.Service-issued
// JWT into a cookie and confirms the middleware extracts and validates it
// correctly. Catches subtle base64 / URL-encoding issues in the cookie
// transport layer that mock-based tests would miss.
func TestAuthMiddleware_RealJWTRoundtripViaCookie(t *testing.T) {
	// Spin up a real auth.Service backed by in-memory SQLite. The DSN uses
	// the shared-cache URI form and pool is pinned to one connection: with
	// plain ":memory:" each pool connection gets its own isolated DB, so
	// schema bootstrap on connection A is invisible to auth.Service queries
	// on connection B and the test fails with "no such table".
	db, err := sqlx.Connect("sqlite", "file::memory:?cache=shared")
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
			full_name TEXT NOT NULL, password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user', status TEXT NOT NULL DEFAULT 'active',
			last_login TIMESTAMP, created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL
		);
		CREATE TABLE sessions (
			id TEXT PRIMARY KEY, user_id TEXT NOT NULL, token TEXT NOT NULL UNIQUE,
			expires_at TIMESTAMP NOT NULL, ip_address TEXT, user_agent TEXT,
			created_at TIMESTAMP NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);
	`)
	require.NoError(t, err)

	logger := utils.NewLogger("", false)
	authStore := auth.NewSQLStore(db)
	authSvc := auth.NewService(authStore, "test-secret-32-bytes-of-padding!!", "test", logger)

	ctx := t.Context()
	_, err = authSvc.CreateUser(ctx, &auth.CreateUserRequest{
		Username: "rt", Email: "rt@example.com", FullName: "Roundtrip", Password: "ValidPass123!",
	})
	require.NoError(t, err)
	resp, err := authSvc.Login(ctx, &auth.LoginRequest{Username: "rt", Password: "ValidPass123!"}, "127.0.0.1", "test")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Token)

	// Place the real JWT in a cookie and run it through AuthMiddleware.
	var captured *auth.User
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = GetUserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: resp.Token})
	w := httptest.NewRecorder()

	AuthMiddleware(authSvc, logger)(handler).ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code,
		"real JWT in cookie must validate end-to-end (catches base64/URL-encoding regressions)")
	require.NotNil(t, captured)
	assert.Equal(t, "rt", captured.Username)
}
