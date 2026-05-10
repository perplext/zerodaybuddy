package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// setupBrowserAuthBackend builds a minimal in-memory SQLite + auth.Service
// for browser-auth tests. Mirrors setupAuthBackend in router_test.go but
// scoped to the handlers package.
func setupBrowserAuthBackend(t *testing.T) *auth.Service {
	t.Helper()

	// modernc.org/sqlite (and SQLite generally) gives every connection its
	// own private in-memory DB when the DSN is plain ":memory:". sqlx pools
	// connections, so schema bootstrap on one connection is invisible to
	// auth.Service queries on another. Use the shared-cache URI DSN AND
	// pin the pool to one connection to be safe — either alone is enough,
	// but the combination is the no-surprises default.
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

	authStore := auth.NewSQLStore(db)
	logger := utils.NewLogger("", false)
	return auth.NewService(authStore, "test-secret-32-bytes-of-padding!!", "test", logger)
}

// minimalLoginTmpl is the smallest template that has the markers tests check
// for (LoggedOut banner, Error banner). The real template ships in U3 under
// internal/web/embedded/templates/login.tmpl; the handler only needs *any*
// template named "login.tmpl" — these tests provide their own to stay
// self-contained.
const minimalLoginTmpl = `{{define "login.tmpl"}}` +
	`<form method="post" action="/login">` +
	`{{if .LoggedOut}}<p>logged-out-banner</p>{{end}}` +
	`{{if .Error}}<p>error: {{.Error}}</p>{{end}}` +
	`<input name="username">` +
	`<input name="password" type="password">` +
	`<button type="submit">Log in</button>` +
	`</form>` +
	`{{end}}`

func makeLoginTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("").Parse(minimalLoginTmpl)
	require.NoError(t, err)
	return tmpl
}

// createTestUser is a thin wrapper around auth.Service.CreateUser used by
// the happy-path tests.
func createTestUser(t *testing.T, ctx context.Context, svc *auth.Service, username, password string) {
	t.Helper()
	_, err := svc.CreateUser(ctx, &auth.CreateUserRequest{
		Username: username,
		Email:    username + "@test.example.com",
		FullName: username,
		Password: password,
	})
	require.NoError(t, err)
}

// -- GET /login --

func TestBrowserAuth_GET_RendersForm(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), false, false)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	h.loginForm(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `<form method="post" action="/login">`)
	assert.NotContains(t, body, "logged-out-banner")
	assert.NotContains(t, body, "error:")
}

func TestBrowserAuth_GET_AlreadyAuthedRedirectsToRoot(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), false, false)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	user := &auth.User{ID: "u1", Username: "alice", Role: auth.RoleUser, Status: auth.StatusActive}
	req = req.WithContext(middleware.ContextWithUser(req.Context(), user))

	w := httptest.NewRecorder()
	h.loginForm(w, req)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))
}

func TestBrowserAuth_GET_LoggedOutQueryShowsBanner(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), false, false)

	req := httptest.NewRequest(http.MethodGet, "/login?logged-out=1", nil)
	w := httptest.NewRecorder()
	h.loginForm(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "logged-out-banner")
}

// -- POST /login --

func TestBrowserAuth_POST_HappyPathSetsCookie(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	createTestUser(t, t.Context(), svc, "alice", "ValidPass123!")

	for _, secure := range []bool{false, true} {
		t.Run(secureLabel(secure), func(t *testing.T) {
			h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), secure, false)

			form := url.Values{"username": {"alice"}, "password": {"ValidPass123!"}}
			req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			w := httptest.NewRecorder()
			h.login(w, req)

			require.Equal(t, http.StatusSeeOther, w.Code, "body: %s", w.Body.String())
			assert.Equal(t, "/", w.Header().Get("Location"))

			// Inspect Set-Cookie
			cookies := w.Result().Cookies()
			require.Len(t, cookies, 1)
			cookie := cookies[0]
			assert.Equal(t, middleware.SessionCookieName, cookie.Name)
			assert.NotEmpty(t, cookie.Value, "cookie should carry the JWT")
			assert.True(t, cookie.HttpOnly, "session cookie must be HttpOnly")
			assert.Equal(t, http.SameSiteStrictMode, cookie.SameSite)
			assert.Equal(t, "/", cookie.Path)
			assert.Equal(t, sessionCookieMaxAge, cookie.MaxAge)
			assert.Equal(t, secure, cookie.Secure,
				"Secure flag should mirror the cookieSecure constructor arg")
		})
	}
}

func TestBrowserAuth_POST_InvalidCredentialsShowsGenericError(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	createTestUser(t, t.Context(), svc, "alice", "ValidPass123!")
	h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), false, false)

	form := url.Values{"username": {"alice"}, "password": {"WrongPassword!"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	h.login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "error: Invalid username or password",
		"error must be generic — must NOT leak whether username or password was wrong")
	// No cookie set on failed login
	assert.Empty(t, w.Result().Cookies(), "no cookie should be set on failed login")
}

func TestBrowserAuth_POST_NonexistentUserShowsSameGenericError(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), false, false)

	form := url.Values{"username": {"nobody"}, "password": {"anything!"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	h.login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "error: Invalid username or password",
		"nonexistent user must produce the same error as wrong password")
}

func TestBrowserAuth_POST_EmptyFieldsRejected(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), false, false)

	form := url.Values{"username": {""}, "password": {""}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	h.login(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid username or password")
}

// -- POST /logout --

func TestBrowserAuth_POST_LogoutClearsCookieAndRevokesSession(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	createTestUser(t, t.Context(), svc, "alice", "ValidPass123!")

	// Login first to get a real session
	resp, err := svc.Login(t.Context(), &auth.LoginRequest{Username: "alice", Password: "ValidPass123!"}, "127.0.0.1", "test")
	require.NoError(t, err)
	require.NotEmpty(t, resp.Token)

	h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), false, false)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: resp.Token})

	w := httptest.NewRecorder()
	h.logout(w, req)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login?logged-out=1", w.Header().Get("Location"))

	// Cookie cleared. Browsers only "delete" a cookie when the clearing
	// Set-Cookie matches the original on Path + Domain + Secure + SameSite
	// — assert all of those, not just the value, otherwise a regression
	// that drops Path="/" would leave the original cookie in the browser
	// even though this test says "cleared".
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	cleared := cookies[0]
	assert.Equal(t, middleware.SessionCookieName, cleared.Name)
	assert.Empty(t, cleared.Value)
	assert.Equal(t, "/", cleared.Path)
	assert.True(t, cleared.HttpOnly, "clear cookie must keep HttpOnly")
	assert.Equal(t, http.SameSiteStrictMode, cleared.SameSite)
	assert.True(t, cleared.MaxAge < 0 || cleared.MaxAge == 0,
		"cookie must be deleted via MaxAge<=0")

	// Session revoked: validating the previously-valid token now fails.
	_, err = svc.ValidateToken(t.Context(), resp.Token)
	assert.Error(t, err, "session must be revoked server-side after logout")
}

func TestBrowserAuth_POST_LogoutWithoutCookieIsIdempotent(t *testing.T) {
	svc := setupBrowserAuthBackend(t)
	h := NewBrowserAuthHandler(svc, makeLoginTmpl(t), utils.NewLogger("", false), false, false)

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	w := httptest.NewRecorder()
	h.logout(w, req)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login?logged-out=1", w.Header().Get("Location"))
	// Still sets the cleared cookie defensively. Same Path/SameSite/HttpOnly
	// asserts as the with-cookie path so a regression on either path is
	// caught equally.
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	cleared := cookies[0]
	assert.Empty(t, cleared.Value)
	assert.Equal(t, "/", cleared.Path)
	assert.True(t, cleared.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, cleared.SameSite)
}

// -- helpers --

func secureLabel(s bool) string {
	if s {
		return "secure_TLS_on"
	}
	return "secure_TLS_off"
}
