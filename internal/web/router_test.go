package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/pkg/config"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

// setupAuthBackend builds an in-memory SQLite DB plus a real auth.Service.
// Mirrors the schema in internal/auth/service_test.go:setupTestDB.
func setupAuthBackend(t *testing.T) *auth.Service {
	t.Helper()

	db, err := sqlx.Connect("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			full_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			status TEXT NOT NULL DEFAULT 'active',
			last_login TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);
		CREATE TABLE sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			expires_at TIMESTAMP NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMP NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);
	`)
	require.NoError(t, err)

	store := auth.NewSQLStore(db)
	logger := utils.NewLogger("", false)
	return auth.NewService(store, "test-secret-32-bytes-of-padding!!", "test-issuer", logger)
}

// newTestServerWithAuth constructs a Server with a real in-memory auth backend.
// All six /api/auth/* routes are wired and reachable.
func newTestServerWithAuth(t *testing.T) *Server {
	t.Helper()
	authSvc := setupAuthBackend(t)
	return NewServer(config.WebServerConfig{}, Dependencies{AuthService: authSvc}, utils.NewLogger("", false))
}

func doRequest(t *testing.T, srv *Server, method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	var req *http.Request
	if bodyReader == nil {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, bodyReader)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)
	return w
}

// -- Route registration: every wired endpoint returns something OTHER than 404 --

func TestRouter_AllSixAuthRoutesRegistered(t *testing.T) {
	srv := newTestServerWithAuth(t)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"login", http.MethodPost, "/api/auth/login"},
		{"register", http.MethodPost, "/api/auth/register"},
		{"refresh", http.MethodPost, "/api/auth/refresh"},
		{"logout", http.MethodPost, "/api/auth/logout"},
		{"profile", http.MethodGet, "/api/auth/profile"},
		{"change-password", http.MethodPost, "/api/auth/change-password"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doRequest(t, srv, tt.method, tt.path, nil, nil)
			assert.NotEqual(t, http.StatusNotFound, w.Code,
				"route %s %s must be registered (expected anything but 404)", tt.method, tt.path)
		})
	}
}

func TestRouter_NilAuthServiceSkipsAuthRoutes(t *testing.T) {
	srv := NewServer(config.WebServerConfig{}, Dependencies{}, utils.NewLogger("", false))

	// Auth routes 404 because they were never registered
	w := doRequest(t, srv, http.MethodPost, "/api/auth/login", nil, nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// /health still works
	w = doRequest(t, srv, http.MethodGet, "/health", nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

// -- Method routing (Go 1.22 enhanced ServeMux semantics) --

func TestRouter_WrongMethodReturns405(t *testing.T) {
	srv := newTestServerWithAuth(t)

	// /api/auth/login is registered POST-only; GET should be 405
	w := doRequest(t, srv, http.MethodGet, "/api/auth/login", nil, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)

	// /api/auth/profile is GET-only; POST should be 405
	w = doRequest(t, srv, http.MethodPost, "/api/auth/profile", nil, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestRouter_UnknownPathReturns404(t *testing.T) {
	srv := newTestServerWithAuth(t)

	w := doRequest(t, srv, http.MethodGet, "/api/auth/nonexistent", nil, nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// -- Auth middleware behavior on protected routes --

func TestRouter_ProtectedRouteRequiresAuthHeader(t *testing.T) {
	srv := newTestServerWithAuth(t)

	w := doRequest(t, srv, http.MethodGet, "/api/auth/profile", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

func TestRouter_ProtectedRouteRejectsBadBearerFormat(t *testing.T) {
	srv := newTestServerWithAuth(t)

	// T2-3 (U1) changed behavior: a malformed Authorization header falls
	// through to the cookie check. With no cookie present, the response is
	// "Authorization header required" (same as no auth at all). Pre-T2-3
	// this returned a distinct "Invalid authorization header format" message.
	w := doRequest(t, srv, http.MethodGet, "/api/auth/profile", nil, map[string]string{
		"Authorization": "Basic dXNlcjpwYXNz",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Authorization header required")
}

func TestRouter_ProtectedRouteRejectsInvalidToken(t *testing.T) {
	srv := newTestServerWithAuth(t)

	w := doRequest(t, srv, http.MethodGet, "/api/auth/profile", nil, map[string]string{
		"Authorization": "Bearer not-a-real-token",
	})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired token")
}

// -- Security header presence on every response --

func TestRouter_SecurityHeadersPresentOn200(t *testing.T) {
	srv := newTestServerWithAuth(t)

	w := doRequest(t, srv, http.MethodGet, "/health", nil, nil)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
	assert.NotEmpty(t, w.Header().Get("Referrer-Policy"))
}

// Critical middleware-order test: SecurityHeaders must run BEFORE AuthMiddleware
// short-circuits on a 401, otherwise unauthenticated responses lack the security
// posture the rest of the API has.
func TestRouter_SecurityHeadersPresentOn401(t *testing.T) {
	srv := newTestServerWithAuth(t)

	w := doRequest(t, srv, http.MethodGet, "/api/auth/profile", nil, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"),
		"security headers must be set before AuthMiddleware short-circuits")
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
}

// -- MaxBodySize enforcement --

func TestRouter_OversizedBodyReturns413(t *testing.T) {
	srv := newTestServerWithAuth(t)

	// 2 MiB body — over the 1 MiB default limit
	body := bytes.Repeat([]byte("x"), 2<<20)
	w := doRequest(t, srv, http.MethodPost, "/api/auth/login", body, map[string]string{
		"Content-Type": "application/json",
	})
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

// -- CORS: opt-in via AllowedOrigins --

func TestRouter_CORSDisabledWhenNoAllowedOrigins(t *testing.T) {
	srv := newTestServerWithAuth(t)

	w := doRequest(t, srv, http.MethodGet, "/health", nil, map[string]string{
		"Origin": "http://localhost:3000",
	})
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"),
		"CORS header must NOT be set when AllowedOrigins is empty")
}

func TestRouter_CORSEnabledWhenOriginAllowed(t *testing.T) {
	authSvc := setupAuthBackend(t)
	srv := NewServer(
		config.WebServerConfig{AllowedOrigins: []string{"http://localhost:3000"}},
		Dependencies{AuthService: authSvc},
		utils.NewLogger("", false),
	)

	w := doRequest(t, srv, http.MethodGet, "/health", nil, map[string]string{
		"Origin": "http://localhost:3000",
	})
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

// TestRouter_CORSPreflightOnAuthRouteSucceeds proves the fix for the CodeRabbit
// finding on PR #19: Go 1.22 ServeMux's method-prefixed route patterns
// ("POST /api/auth/login") do NOT match OPTIONS preflight requests. Per-route
// middleware never runs for OPTIONS in that setup, so a browser's CORS preflight
// would 405 before CORS could respond. Fix: CORS is wrapped at the mux level
// in buildRouter (see Server.applyCORS), making it run for every request
// including OPTIONS regardless of registered method handlers.
func TestRouter_CORSPreflightOnAuthRouteSucceeds(t *testing.T) {
	authSvc := setupAuthBackend(t)
	srv := NewServer(
		config.WebServerConfig{AllowedOrigins: []string{"http://localhost:3000"}},
		Dependencies{AuthService: authSvc},
		utils.NewLogger("", false),
	)

	// OPTIONS preflight to a POST-only route. Without the fix, this would 405.
	w := doRequest(t, srv, http.MethodOptions, "/api/auth/login", nil, map[string]string{
		"Origin":                         "http://localhost:3000",
		"Access-Control-Request-Method":  "POST",
		"Access-Control-Request-Headers": "Authorization, Content-Type",
	})

	// CORS middleware short-circuits OPTIONS with 204 + headers when the origin
	// is in the allow-list (see middleware.CORS implementation in security.go).
	assert.Equal(t, http.StatusNoContent, w.Code,
		"OPTIONS preflight must succeed (204), not 405; CORS must run before method-pattern dispatch")
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Methods"))
	assert.NotEmpty(t, w.Header().Get("Access-Control-Allow-Headers"))
}

// TestRouter_CORSPreflightOnUnknownRouteStillSucceeds — the CORS middleware wraps
// the entire mux, so even OPTIONS preflight to a path that has no registered
// handler returns the CORS 204 (preflight is browser-driven and shouldn't reveal
// path existence). Acts as a sanity check that mux-level wrapping is functioning
// regardless of underlying route registration.
func TestRouter_CORSPreflightOnUnknownRouteStillSucceeds(t *testing.T) {
	authSvc := setupAuthBackend(t)
	srv := NewServer(
		config.WebServerConfig{AllowedOrigins: []string{"http://localhost:3000"}},
		Dependencies{AuthService: authSvc},
		utils.NewLogger("", false),
	)

	w := doRequest(t, srv, http.MethodOptions, "/api/totally-not-registered", nil, map[string]string{
		"Origin":                        "http://localhost:3000",
		"Access-Control-Request-Method": "POST",
	})

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "http://localhost:3000", w.Header().Get("Access-Control-Allow-Origin"))
}

// =============================================================================
// T2-2 — Data-model REST handlers integration tests
// =============================================================================

// setupCombinedBackend builds a fresh on-disk SQLite store (in t.TempDir for
// per-test isolation) with migration-applied schema (which includes the auth
// tables) and an auth.Service backed by the same DB. Returns the concrete
// *storage.SQLiteStore so callers can reach .DB() for direct schema mutations
// (e.g., elevating a user's role for admin-tier tests).
func setupCombinedBackend(t *testing.T) (*storage.SQLiteStore, *auth.Service) {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	authStore := auth.NewSQLStore(store.DB())
	logger := utils.NewLogger("", false)
	authSvc := auth.NewService(authStore, "test-secret-32-bytes-of-padding!!", "test-issuer", logger)
	return store, authSvc
}

// newTestServerWithStoreAndAuth builds a Server with both Store and AuthService
// wired, suitable for full data-API tests.
func newTestServerWithStoreAndAuth(t *testing.T) (*Server, *storage.SQLiteStore, *auth.Service) {
	t.Helper()
	store, authSvc := setupCombinedBackend(t)
	srv := NewServer(
		config.WebServerConfig{},
		Dependencies{AuthService: authSvc, Store: store},
		utils.NewLogger("", false),
	)
	return srv, store, authSvc
}

// loginAs creates a user (with RoleUser regardless of the requested role —
// auth.Service.CreateUser always assigns RoleUser per its self-registration
// policy) and returns a bearer token. The role parameter is honored by
// elevating the user's role directly via the auth store after creation;
// auth.Service has no admin endpoint exposed, so test setup uses the store
// API directly.
//
// Skips creation if the user already exists (e.g., the migration-seeded
// "admin" user) and just logs in.
func loginAs(t *testing.T, authSvc *auth.Service, store *storage.SQLiteStore, username, password string, role auth.UserRole) string {
	t.Helper()
	ctx := t.Context()

	// Try CreateUser; tolerate already-exists.
	_, createErr := authSvc.CreateUser(ctx, &auth.CreateUserRequest{
		Username: username,
		Email:    username + "@example.com",
		FullName: username,
		Password: password,
	})
	if createErr != nil && createErr.Error() != "username already exists" {
		t.Fatalf("CreateUser(%s) unexpected error: %v", username, createErr)
	}

	// If a non-default role was requested, elevate via the underlying auth
	// store (the auth.Service deliberately does not expose role assignment).
	if role != auth.RoleUser {
		authStore := auth.NewSQLStore(store.DB())
		u, err := authStore.GetUserByUsername(ctx, username)
		require.NoError(t, err)
		u.Role = role
		require.NoError(t, authStore.UpdateUser(ctx, u))
	}

	resp, err := authSvc.Login(ctx, &auth.LoginRequest{
		Username: username,
		Password: password,
	}, "127.0.0.1", "test-agent")
	require.NoError(t, err)
	return resp.Token
}

func TestRouter_AllDataRoutesRegistered(t *testing.T) {
	srv, store, authSvc := newTestServerWithStoreAndAuth(t)
	token := loginAs(t, authSvc, store, "alice", "ValidPass123!", auth.RoleUser)
	authHeader := map[string]string{"Authorization": "Bearer " + token}

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"projects.list", http.MethodGet, "/api/projects"},
		{"projects.get", http.MethodGet, "/api/projects/some-id"},
		{"projects.create", http.MethodPost, "/api/projects"},
		{"projects.delete", http.MethodDelete, "/api/projects/some-id"},
		{"hosts.list", http.MethodGet, "/api/projects/some-id/hosts"},
		{"hosts.get", http.MethodGet, "/api/hosts/some-id"},
		{"endpoints.list", http.MethodGet, "/api/projects/some-id/endpoints"},
		{"endpoints.get", http.MethodGet, "/api/endpoints/some-id"},
		{"findings.list", http.MethodGet, "/api/projects/some-id/findings"},
		{"findings.get", http.MethodGet, "/api/findings/some-id"},
		{"findings.patch", http.MethodPatch, "/api/findings/some-id"},
		{"tasks.list", http.MethodGet, "/api/projects/some-id/tasks"},
		{"tasks.get", http.MethodGet, "/api/tasks/some-id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := doRequest(t, srv, tt.method, tt.path, nil, authHeader)
			// A registered route can legitimately return 404 (entity-not-found
			// from the handler). Distinguish that from an unregistered route
			// (router default 404, plain-text body) by checking Content-Type:
			// any registered handler in this PR returns application/json.
			ct := w.Header().Get("Content-Type")
			if w.Code == http.StatusNotFound {
				assert.Contains(t, ct, "application/json",
					"route %s %s appears unregistered: 404 with non-JSON body %q (got: %s)",
					tt.method, tt.path, ct, w.Body.String())
			}
		})
	}
}

func TestRouter_NilStoreSkipsDataRoutes(t *testing.T) {
	store, authSvc := setupCombinedBackend(t)
	// Server constructed WITHOUT Store — even though store is wired into
	// auth, the server's view of dependencies omits it.
	srv := NewServer(
		config.WebServerConfig{},
		Dependencies{AuthService: authSvc},
		utils.NewLogger("", false),
	)
	token := loginAs(t, authSvc, store, "alice", "ValidPass123!", auth.RoleUser)
	authHeader := map[string]string{"Authorization": "Bearer " + token}

	// Data routes 404 (never registered)
	w := doRequest(t, srv, http.MethodGet, "/api/projects", nil, authHeader)
	assert.Equal(t, http.StatusNotFound, w.Code)

	// Auth routes still work (login already returned a token)
	w = doRequest(t, srv, http.MethodGet, "/api/auth/profile", nil, authHeader)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRouter_FullProjectLifecycle(t *testing.T) {
	srv, store, authSvc := newTestServerWithStoreAndAuth(t)
	// NB: migration 004 seeds a default user "admin" — use a distinct
	// admin-test username to avoid the username-uniqueness conflict.
	// auth.Service.CreateUser always assigns RoleUser; loginAs elevates
	// admin-tier users via the auth store directly.
	userToken := loginAs(t, authSvc, store, "alice", "ValidPass123!", auth.RoleUser)
	adminToken := loginAs(t, authSvc, store, "admintest", "ValidPass123!", auth.RoleAdmin)

	// User creates a manual project (manual mode requires a non-empty scope,
	// which also exercises scope round-tripping through SQLite).
	createBody, _ := json.Marshal(map[string]any{
		"name":     "lifecycle-test",
		"platform": "manual",
		"scope": map[string]any{
			"in_scope": []map[string]any{
				{"type": "domain", "value": "example.com"},
			},
		},
	})
	w := doRequest(t, srv, http.MethodPost, "/api/projects", createBody, map[string]string{
		"Authorization": "Bearer " + userToken,
		"Content-Type":  "application/json",
	})
	require.Equal(t, http.StatusCreated, w.Code, "create failed: %s", w.Body.String())

	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	require.NotEmpty(t, created.ID, "create response must include id")

	// User can list and see the project
	w = doRequest(t, srv, http.MethodGet, "/api/projects", nil, map[string]string{
		"Authorization": "Bearer " + userToken,
	})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), created.ID)

	// User can get the project by id
	w = doRequest(t, srv, http.MethodGet, "/api/projects/"+created.ID, nil, map[string]string{
		"Authorization": "Bearer " + userToken,
	})
	assert.Equal(t, http.StatusOK, w.Code)

	// User CANNOT delete (admin required)
	w = doRequest(t, srv, http.MethodDelete, "/api/projects/"+created.ID, nil, map[string]string{
		"Authorization": "Bearer " + userToken,
	})
	assert.Equal(t, http.StatusForbidden, w.Code, "delete as RoleUser must be 403")

	// Admin CAN delete
	w = doRequest(t, srv, http.MethodDelete, "/api/projects/"+created.ID, nil, map[string]string{
		"Authorization": "Bearer " + adminToken,
	})
	assert.Equal(t, http.StatusNoContent, w.Code, "delete as admin must be 204")

	// Project no longer exists
	w = doRequest(t, srv, http.MethodGet, "/api/projects/"+created.ID, nil, map[string]string{
		"Authorization": "Bearer " + userToken,
	})
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestRouter_DataRouteEnforcesAuth — pick one new route and confirm it goes
// through AuthMiddleware. AuthMiddleware on the authedChain returns 401 for
// requests without a valid bearer token, proving the wiring picked up the
// per-route middleware stack rather than skipping it.
func TestRouter_DataRouteEnforcesAuth(t *testing.T) {
	srv, _, _ := newTestServerWithStoreAndAuth(t)

	w := doRequest(t, srv, http.MethodGet, "/api/projects", nil, nil) // no Authorization header
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestRouter_DataRouteHasSecurityHeaders — same pattern as the auth-route
// security-header test from T2-1, applied to a data route. Proves the
// publicChain (wrapped by authedChain) is correctly applied to data handlers.
func TestRouter_DataRouteHasSecurityHeaders(t *testing.T) {
	srv, store, authSvc := newTestServerWithStoreAndAuth(t)
	token := loginAs(t, authSvc, store, "alice", "ValidPass123!", auth.RoleUser)

	w := doRequest(t, srv, http.MethodGet, "/api/projects", nil, map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
	assert.Equal(t, "default-src 'self'", w.Header().Get("Content-Security-Policy"))
}

// -- Happy path: login then use returned token to access profile --

func TestRouter_LoginThenProfileWithTokenSucceeds(t *testing.T) {
	authSvc := setupAuthBackend(t)
	_ = authSvc // keep auth-only setup; this test predates the loginAs+store helper
	srv := NewServer(config.WebServerConfig{}, Dependencies{AuthService: authSvc}, utils.NewLogger("", false))

	// Create a user directly via the auth service to avoid coupling this test
	// to the Register endpoint's exact JSON shape.
	_, err := authSvc.CreateUser(t.Context(), &auth.CreateUserRequest{
		Username: "alice",
		Email:    "alice@example.com",
		FullName: "Alice Anderson",
		Password: "ValidPass123!",
		Role:     auth.RoleUser,
	})
	require.NoError(t, err)

	// Login
	loginBody, _ := json.Marshal(map[string]string{
		"username": "alice",
		"password": "ValidPass123!",
	})
	w := doRequest(t, srv, http.MethodPost, "/api/auth/login", loginBody, map[string]string{
		"Content-Type": "application/json",
	})
	require.Equal(t, http.StatusOK, w.Code, "login failed: %s", w.Body.String())

	var loginResp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &loginResp))
	token, ok := loginResp["access_token"].(string)
	if !ok {
		// Tolerate alternate field names in case the response shape uses "token"
		token, _ = loginResp["token"].(string)
	}
	require.NotEmpty(t, token, "login response must include a token (got: %s)", w.Body.String())

	// Use token to access profile
	w = doRequest(t, srv, http.MethodGet, "/api/auth/profile", nil, map[string]string{
		"Authorization": "Bearer " + token,
	})
	assert.Equal(t, http.StatusOK, w.Code, "profile access failed: %s", w.Body.String())
	assert.Contains(t, strings.ToLower(w.Body.String()), "alice")
}
