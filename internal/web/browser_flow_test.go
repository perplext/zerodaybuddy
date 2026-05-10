package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
)

// End-to-end browser-flow integration tests for the T2-3 dashboard.
// Composes the actual NewServer + buildRouter pipeline with a real SQLite
// store, real auth.Service, and real templates from EmbeddedFS. Manages
// cookie propagation between requests by hand — no http.Client cookie jar
// because httptest doesn't run a real server.

// doBrowserRequest issues a request against srv with optional form body and
// optional cookies. Returns the recorder so callers can inspect status,
// headers (including Set-Cookie), and body.
func doBrowserRequest(t *testing.T, srv *Server, method, path string, body []byte, contentType string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(w, req)
	return w
}

// extractSessionCookie pulls the zdb_session cookie from a response, or
// returns nil if not present.
func extractSessionCookie(w *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == middleware.SessionCookieName {
			return c
		}
	}
	return nil
}

// seedProjectWithFinding inserts one project + one finding directly via the
// store. Returns the project id and finding id for use in subsequent
// browser requests.
func seedProjectWithFinding(t *testing.T, store *storage.SQLiteStore) (projectID, findingID string) {
	t.Helper()
	now := time.Now()

	project := &models.Project{
		Name:        "Browser Flow Test Project",
		Handle:      "bft-project",
		Platform:    "hackerone",
		Type:        models.ProjectTypeBugBounty,
		Description: "End-to-end browser flow seed",
		StartDate:   now,
		Status:      models.ProjectStatusActive,
		Scope: models.Scope{
			InScope: []models.Asset{
				{Type: models.AssetTypeDomain, Value: "example.com"},
			},
		},
	}
	require.NoError(t, store.CreateProject(t.Context(), project))
	require.NotEmpty(t, project.ID, "store should populate project.ID on create")

	finding := &models.Finding{
		ProjectID:   project.ID,
		Type:        models.FindingTypeVulnerability,
		Title:       "Reflected XSS in /search",
		Description: "Echoed query parameter without encoding",
		Severity:    models.SeverityHigh,
		Confidence:  models.ConfidenceMedium,
		Status:      models.FindingStatusNew,
		FoundBy:     "browser-flow-test",
		FoundAt:     now,
	}
	require.NoError(t, store.CreateFinding(t.Context(), finding))
	require.NotEmpty(t, finding.ID, "store should populate finding.ID on create")

	return project.ID, finding.ID
}

// TestBrowserFlow_FullLoginToTriageToLogout is the headline end-to-end test.
// It exercises the entire T2-3 user journey:
//
//  1. Anonymous GET / → 303 to /login.
//  2. GET /login → 200 + form.
//  3. POST /login with valid creds → 303 / + Set-Cookie zdb_session.
//  4. Authenticated GET / → 200 + dashboard listing the seeded project.
//  5. GET /projects/{id} → 200 + finding row with HTMX triage select.
//  6. PATCH /api/findings/{id} via cookie auth → 200; finding.Status updated.
//  7. POST /logout → 303 /login?logged-out=1 + cleared cookie + revoked session.
//  8. Re-using the revoked cookie → 303 to /login (server-side invalidation).
func TestBrowserFlow_FullLoginToTriageToLogout(t *testing.T) {
	srv, store, authSvc := newTestServerWithStoreAndAuth(t)

	// Pre-create the user. The browser will log in as alice.
	_, err := authSvc.CreateUser(t.Context(), &auth.CreateUserRequest{
		Username: "alice",
		Email:    "alice@example.com",
		FullName: "Alice Anderson",
		Password: "ValidPass123!",
	})
	require.NoError(t, err)

	projectID, findingID := seedProjectWithFinding(t, store)

	// 1. Anonymous GET / → 303 to /login.
	w := doBrowserRequest(t, srv, http.MethodGet, "/", nil, "", nil)
	require.Equal(t, http.StatusSeeOther, w.Code,
		"anonymous root must redirect to login, body: %s", w.Body.String())
	assert.Equal(t, "/login", w.Header().Get("Location"))

	// 2. GET /login → 200 + form.
	w = doBrowserRequest(t, srv, http.MethodGet, "/login", nil, "", nil)
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `<form method="post" action="/login">`,
		"login form must render so users can submit credentials")

	// 3. POST /login with valid creds → 303 / + Set-Cookie zdb_session.
	form := url.Values{"username": {"alice"}, "password": {"ValidPass123!"}}
	w = doBrowserRequest(t, srv, http.MethodPost, "/login",
		[]byte(form.Encode()), "application/x-www-form-urlencoded", nil)
	require.Equal(t, http.StatusSeeOther, w.Code, "login should redirect; body: %s", w.Body.String())
	assert.Equal(t, "/", w.Header().Get("Location"))
	sessionCookie := extractSessionCookie(w)
	require.NotNil(t, sessionCookie, "login must set zdb_session cookie")
	require.NotEmpty(t, sessionCookie.Value)
	assert.True(t, sessionCookie.HttpOnly, "session cookie must be HttpOnly")
	assert.Equal(t, http.SameSiteStrictMode, sessionCookie.SameSite)

	// 4. Authenticated GET / → 200 + dashboard with seeded project.
	w = doBrowserRequest(t, srv, http.MethodGet, "/", nil, "",
		[]*http.Cookie{sessionCookie})
	require.Equal(t, http.StatusOK, w.Code, "authed dashboard should 200; body: %s", w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, "Browser Flow Test Project",
		"dashboard must list the seeded project")
	assert.Contains(t, body, "alice",
		"header partial should show the logged-in user")

	// 5. GET /projects/{id} → 200 + finding row with HTMX triage select.
	w = doBrowserRequest(t, srv, http.MethodGet, "/projects/"+projectID, nil, "",
		[]*http.Cookie{sessionCookie})
	require.Equal(t, http.StatusOK, w.Code, "project detail should 200; body: %s", w.Body.String())
	body = w.Body.String()
	assert.Contains(t, body, "Reflected XSS in /search",
		"finding row must render in the project detail page")
	assert.Contains(t, body, `hx-patch="/api/findings/`+findingID+`"`,
		"triage select must wire HTMX to the per-finding PATCH endpoint")
	assert.Contains(t, body, `hx-ext="json-enc"`,
		"json-enc extension must be wired so the form value goes as JSON")

	// 6. PATCH /api/findings/{id} via cookie auth → 200; finding.Status updated.
	patchBody := []byte(`{"status":"confirmed"}`)
	w = doBrowserRequest(t, srv, http.MethodPatch, "/api/findings/"+findingID,
		patchBody, "application/json", []*http.Cookie{sessionCookie})
	require.Equal(t, http.StatusOK, w.Code,
		"PATCH via cookie should succeed (cookie-or-header auth from U1); body: %s", w.Body.String())

	// Verify the change persisted server-side. This guards against the failure
	// mode where the response says 200 but the store was never written to.
	updated, err := store.GetFinding(t.Context(), findingID)
	require.NoError(t, err)
	assert.Equal(t, models.FindingStatusConfirmed, updated.Status,
		"finding.Status must reflect the PATCH — guards hx-swap=\"none\" + reload pattern")

	// 7. POST /logout → 303 /login?logged-out=1 + cleared cookie.
	w = doBrowserRequest(t, srv, http.MethodPost, "/logout", nil, "",
		[]*http.Cookie{sessionCookie})
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login?logged-out=1", w.Header().Get("Location"))
	cleared := extractSessionCookie(w)
	require.NotNil(t, cleared, "logout must set a cleared cookie")
	assert.Empty(t, cleared.Value, "cleared cookie must have empty value")
	assert.True(t, cleared.MaxAge < 0 || cleared.MaxAge == 0,
		"cleared cookie must use MaxAge<=0 to delete client-side")

	// 8. Re-using the revoked cookie should NOT keep the user logged in.
	// The dashboard handler uses OptionalAuth — when the cookie's session was
	// revoked server-side, the user-context comes back empty and the handler
	// 303s to /login. This proves the logout actually invalidated the session
	// rather than just clearing the client cookie.
	w = doBrowserRequest(t, srv, http.MethodGet, "/", nil, "",
		[]*http.Cookie{sessionCookie}) // intentionally re-using the now-revoked cookie
	require.Equal(t, http.StatusSeeOther, w.Code,
		"revoked session cookie must not grant access; body: %s", w.Body.String())
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

// TestBrowserFlow_LoginRejectsBadCreds covers the negative branch.
func TestBrowserFlow_LoginRejectsBadCreds(t *testing.T) {
	srv, _, authSvc := newTestServerWithStoreAndAuth(t)
	_, err := authSvc.CreateUser(t.Context(), &auth.CreateUserRequest{
		Username: "alice", Email: "alice@example.com",
		FullName: "Alice", Password: "ValidPass123!",
	})
	require.NoError(t, err)

	form := url.Values{"username": {"alice"}, "password": {"WrongPass"}}
	w := doBrowserRequest(t, srv, http.MethodPost, "/login",
		[]byte(form.Encode()), "application/x-www-form-urlencoded", nil)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid username or password")
	assert.Nil(t, extractSessionCookie(w), "no cookie on bad creds")
}

// TestBrowserFlow_ProjectDetailNotFound covers the 404 path through the full
// router stack — proves the handler's NotFound writes propagate.
func TestBrowserFlow_ProjectDetailNotFound(t *testing.T) {
	srv, store, authSvc := newTestServerWithStoreAndAuth(t)
	_, err := authSvc.CreateUser(t.Context(), &auth.CreateUserRequest{
		Username: "alice", Email: "alice@example.com",
		FullName: "Alice", Password: "ValidPass123!",
	})
	require.NoError(t, err)
	_ = store // store is needed to wire the data routes

	form := url.Values{"username": {"alice"}, "password": {"ValidPass123!"}}
	w := doBrowserRequest(t, srv, http.MethodPost, "/login",
		[]byte(form.Encode()), "application/x-www-form-urlencoded", nil)
	require.Equal(t, http.StatusSeeOther, w.Code)
	cookie := extractSessionCookie(w)
	require.NotNil(t, cookie)

	w = doBrowserRequest(t, srv, http.MethodGet, "/projects/does-not-exist",
		nil, "", []*http.Cookie{cookie})
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestBrowserFlow_StaticAssetsServedFromEmbed proves the binary serves its
// vendored CSS/JS without a cwd dependency. Mirrors verification gate #12.
func TestBrowserFlow_StaticAssetsServedFromEmbed(t *testing.T) {
	srv, _, _ := newTestServerWithStoreAndAuth(t)

	for _, asset := range []string{
		"/static/css/pico.min.css",
		"/static/css/zdb.css",
		"/static/js/htmx.min.js",
		"/static/js/json-enc.js",
		"/static/js/zdb.js",
	} {
		t.Run(asset, func(t *testing.T) {
			w := doBrowserRequest(t, srv, http.MethodGet, asset, nil, "", nil)
			require.Equal(t, http.StatusOK, w.Code, "asset %s should be served", asset)
			assert.NotEmpty(t, w.Body.Bytes(), "%s body should be non-empty", asset)
		})
	}
}

// TestBrowserFlow_AuthorizationHeaderStillWorks verifies that the U1
// "cookie OR header" change didn't regress the API client path. JSON API
// clients still use Bearer tokens; this test proves the header path
// continues to authenticate even when no cookie is present.
func TestBrowserFlow_AuthorizationHeaderStillWorks(t *testing.T) {
	srv, store, authSvc := newTestServerWithStoreAndAuth(t)
	token := loginAs(t, authSvc, store, "alice", "ValidPass123!", auth.RoleUser)

	w := doBrowserRequest(t, srv, http.MethodGet, "/api/auth/profile", nil, "", nil)
	require.Equal(t, http.StatusUnauthorized, w.Code, "no auth → 401")

	// Now with the bearer header (no cookie attached).
	req := httptest.NewRequest(http.MethodGet, "/api/auth/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.buildRouter().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "header auth must still work; body: %s", rec.Body.String())
	assert.Contains(t, strings.ToLower(rec.Body.String()), "alice")
}
