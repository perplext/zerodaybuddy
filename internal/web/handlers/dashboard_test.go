package handlers

import (
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// minimalDashboardTmpl is a stand-in for the production dashboard.tmpl that
// only carries the markers the tests assert on. Decoupling test from the
// real template means UI tweaks in dashboard.tmpl don't break handler-logic
// coverage.
const minimalDashboardTmpl = `{{define "dashboard.tmpl"}}` +
	`<h1>Projects</h1>` +
	`{{if .Error}}<p class="banner-error">{{.Error}}</p>{{end}}` +
	`{{if .Projects}}<ul>{{range .Projects}}<li data-handle="{{.Handle}}" data-status="{{.Status}}">{{.Name}}</li>{{end}}</ul>{{end}}` +
	`<section class="cli-panel"><code>zerodaybuddy project create</code></section>` +
	`{{if .User}}<span data-username="{{.User.Username}}"></span>{{end}}` +
	`{{end}}`

func makeDashboardTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("").Parse(minimalDashboardTmpl)
	require.NoError(t, err)
	return tmpl
}

func makeDashboardHandler(t *testing.T, store dashboardStore) *DashboardHandler {
	t.Helper()
	return &DashboardHandler{
		store:  store,
		tmpl:   makeDashboardTmpl(t),
		logger: utils.NewLogger("", false),
	}
}

func authedRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	user := &auth.User{ID: "u1", Username: "alice", Role: auth.RoleUser, Status: auth.StatusActive}
	return req.WithContext(middleware.ContextWithUser(req.Context(), user))
}

// -- auth gate --

func TestDashboard_UnauthenticatedRedirectsToLogin(t *testing.T) {
	h := makeDashboardHandler(t, newFakeStore())

	req := httptest.NewRequest(http.MethodGet, "/", nil) // no user in context
	w := httptest.NewRecorder()
	h.index(w, req)

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

// -- empty state --

func TestDashboard_AuthedEmptyProjectListRendersCLIPanel(t *testing.T) {
	h := makeDashboardHandler(t, newFakeStore()) // no projects

	w := httptest.NewRecorder()
	h.index(w, authedRequest(http.MethodGet, "/"))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, `<h1>Projects</h1>`)
	assert.Contains(t, body, `zerodaybuddy project create`,
		"empty-state must still surface the CLI command panel — that's the v1 'create' affordance")
	assert.NotContains(t, body, `<ul>`, "no <ul> when project list is empty")
	assert.Contains(t, body, `data-username="alice"`, "header partial must receive the user")
}

// -- listing + sort --

func TestDashboard_ListsProjectsSortedActiveFirstThenByUpdatedAt(t *testing.T) {
	store := newFakeStore()
	now := time.Now()
	// Insert in deliberately-shuffled order to prove the handler sorts.
	store.projects["a"] = &models.Project{
		ID: "a", Name: "Old Active", Handle: "old-active",
		Status: models.ProjectStatusActive, UpdatedAt: now.Add(-2 * time.Hour),
	}
	store.projects["b"] = &models.Project{
		ID: "b", Name: "Recent Completed", Handle: "recent-completed",
		Status: models.ProjectStatusCompleted, UpdatedAt: now.Add(-1 * time.Hour),
	}
	store.projects["c"] = &models.Project{
		ID: "c", Name: "Recent Active", Handle: "recent-active",
		Status: models.ProjectStatusActive, UpdatedAt: now,
	}
	store.projects["d"] = &models.Project{
		ID: "d", Name: "Archived One", Handle: "archived-one",
		Status: models.ProjectStatusArchived, UpdatedAt: now,
	}
	h := makeDashboardHandler(t, store)

	w := httptest.NewRecorder()
	h.index(w, authedRequest(http.MethodGet, "/"))

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()

	// All four names should appear.
	for _, name := range []string{"Recent Active", "Old Active", "Recent Completed", "Archived One"} {
		assert.Contains(t, body, name)
	}

	// Order check: Recent Active (active, newest) before Old Active (active, older)
	// before Recent Completed (completed) before Archived One.
	require.Less(t, indexOf(body, "Recent Active"), indexOf(body, "Old Active"),
		"within active: newest UpdatedAt first")
	require.Less(t, indexOf(body, "Old Active"), indexOf(body, "Recent Completed"),
		"all active projects before any completed")
	require.Less(t, indexOf(body, "Recent Completed"), indexOf(body, "Archived One"),
		"completed before archived")
}

// -- soft error path --

func TestDashboard_StorageErrorRendersBannerNotFatal(t *testing.T) {
	store := newFakeStore()
	store.listErr = errors.New("simulated db is down")
	h := makeDashboardHandler(t, store)

	w := httptest.NewRecorder()
	h.index(w, authedRequest(http.MethodGet, "/"))

	require.Equal(t, http.StatusOK, w.Code, "soft error: page still renders")
	body := w.Body.String()
	assert.Contains(t, body, "banner-error")
	assert.Contains(t, body, "Could not load projects")
	assert.NotContains(t, body, "simulated db is down",
		"raw error must not leak — surfaces in logs only")
	assert.Contains(t, body, `zerodaybuddy project create`,
		"CLI panel still renders even when listing fails")
}

// -- helpers --

func indexOf(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
