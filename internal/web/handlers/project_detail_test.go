package handlers

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// fakeProjectDetailStore is the in-memory test double for projectDetailStore.
// Keeps each section's data + injectable error so the soft-error contract is
// directly testable.
type fakeProjectDetailStore struct {
	project      *models.Project
	getProjErr   error
	hosts        []*models.Host
	hostsErr     error
	endpoints    []*models.Endpoint
	endpointsErr error
	findings     []*models.Finding
	findingsErr  error
	tasks        []*models.Task
	tasksErr     error
}

func (f *fakeProjectDetailStore) GetProject(_ context.Context, id string) (*models.Project, error) {
	if f.getProjErr != nil {
		return nil, f.getProjErr
	}
	if f.project == nil || f.project.ID != id {
		return nil, storage.ErrNotFound
	}
	return f.project, nil
}

func (f *fakeProjectDetailStore) ListHosts(_ context.Context, _ string) ([]*models.Host, error) {
	return f.hosts, f.hostsErr
}

func (f *fakeProjectDetailStore) ListEndpointsByProject(_ context.Context, _ string) ([]*models.Endpoint, error) {
	return f.endpoints, f.endpointsErr
}

func (f *fakeProjectDetailStore) ListFindings(_ context.Context, _ string) ([]*models.Finding, error) {
	return f.findings, f.findingsErr
}

func (f *fakeProjectDetailStore) ListTasks(_ context.Context, _ string) ([]*models.Task, error) {
	return f.tasks, f.tasksErr
}

const minimalProjectDetailTmpl = `{{define "project_detail.tmpl"}}` +
	`<h1>{{.Project.Name}}</h1>` +
	`<code data-handle>{{.Project.Handle}}</code>` +
	`<section data-section="hosts">` +
	`{{if .HostsErr}}<p class="banner-error">{{.HostsErr}}</p>` +
	`{{else}}{{range .Hosts}}<div data-host>{{.Value}}</div>{{end}}{{end}}` +
	`</section>` +
	`<section data-section="findings">` +
	`{{if .FindingsErr}}<p class="banner-error">{{.FindingsErr}}</p>` +
	`{{else}}{{range .Findings}}<div data-finding>{{.Title}}</div>{{end}}{{end}}` +
	`</section>` +
	`<section data-section="endpoints">` +
	`{{if .EndpointsErr}}<p class="banner-error">{{.EndpointsErr}}</p>` +
	`{{else}}{{range .Endpoints}}<div data-endpoint>{{.URL}}</div>{{end}}{{end}}` +
	`</section>` +
	`<section data-section="tasks">` +
	`{{if .TasksErr}}<p class="banner-error">{{.TasksErr}}</p>` +
	`{{else}}{{range .Tasks}}<div data-task>{{.Name}}</div>{{end}}{{end}}` +
	`</section>` +
	`<pre><code data-clipboard>recon-cmd</code></pre>` +
	`{{if .User}}<span data-username="{{.User.Username}}"></span>{{end}}` +
	`{{end}}`

func makeProjectDetailTmpl(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("").Parse(minimalProjectDetailTmpl)
	require.NoError(t, err)
	return tmpl
}

func makeProjectDetailHandler(t *testing.T, store projectDetailStore) *ProjectDetailHandler {
	t.Helper()
	return &ProjectDetailHandler{
		store:  store,
		tmpl:   makeProjectDetailTmpl(t),
		logger: utils.NewLogger("", false),
	}
}

func detailRequest(method, projectID string, withUser bool) *http.Request {
	req := httptest.NewRequest(method, "/projects/"+projectID, nil)
	req.SetPathValue("id", projectID) // httptest.NewRequest doesn't run mux pattern matching
	if withUser {
		user := &auth.User{ID: "u1", Username: "alice", Role: auth.RoleUser, Status: auth.StatusActive}
		req = req.WithContext(middleware.ContextWithUser(req.Context(), user))
	}
	return req
}

// -- auth gate --

func TestProjectDetail_UnauthenticatedRedirectsToLogin(t *testing.T) {
	h := makeProjectDetailHandler(t, &fakeProjectDetailStore{})

	w := httptest.NewRecorder()
	h.show(w, detailRequest(http.MethodGet, "any-id", false))

	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

// -- not-found / hard error --

func TestProjectDetail_NotFoundReturns404(t *testing.T) {
	store := &fakeProjectDetailStore{} // empty — GetProject returns ErrNotFound
	h := makeProjectDetailHandler(t, store)

	w := httptest.NewRecorder()
	h.show(w, detailRequest(http.MethodGet, "missing", true))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestProjectDetail_GetProjectStorageErrorReturns500(t *testing.T) {
	store := &fakeProjectDetailStore{getProjErr: errors.New("db down")}
	h := makeProjectDetailHandler(t, store)

	w := httptest.NewRecorder()
	h.show(w, detailRequest(http.MethodGet, "any-id", true))

	// Hard error path — unlike per-section soft errors, a missing project root
	// is unrecoverable at this URL.
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// -- happy path --

func TestProjectDetail_RendersAllFourSections(t *testing.T) {
	now := time.Now()
	store := &fakeProjectDetailStore{
		project: &models.Project{
			ID: "p1", Name: "Acme Bug Bounty", Handle: "acme",
			Platform: "hackerone", Status: models.ProjectStatusActive,
			CreatedAt: now, UpdatedAt: now,
		},
		hosts: []*models.Host{
			{ID: "h1", ProjectID: "p1", Value: "api.acme.test", Status: "active"},
		},
		endpoints: []*models.Endpoint{
			{ID: "e1", ProjectID: "p1", URL: "https://api.acme.test/v1", Method: "GET", Status: 200},
		},
		findings: []*models.Finding{
			{ID: "f1", ProjectID: "p1", Title: "Reflected XSS in /search", Severity: models.SeverityHigh, Status: models.FindingStatusNew, FoundAt: now},
		},
		tasks: []*models.Task{
			{ID: "t1", ProjectID: "p1", Name: "subfinder run", Type: "recon", Status: "completed"},
		},
	}
	h := makeProjectDetailHandler(t, store)

	w := httptest.NewRecorder()
	h.show(w, detailRequest(http.MethodGet, "p1", true))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	body := w.Body.String()
	assert.Contains(t, body, "Acme Bug Bounty")
	assert.Contains(t, body, `data-handle`)
	assert.Contains(t, body, "api.acme.test")
	assert.Contains(t, body, "https://api.acme.test/v1")
	assert.Contains(t, body, "Reflected XSS in /search")
	assert.Contains(t, body, "subfinder run")
	assert.Contains(t, body, `data-clipboard>recon-cmd</code>`,
		"the recon CLI panel must render so users have an action affordance")
	assert.Contains(t, body, `data-username="alice"`)
}

// -- soft section errors --

func TestProjectDetail_SoftSectionErrorsRenderInlineAndPageStillLoads(t *testing.T) {
	now := time.Now()
	store := &fakeProjectDetailStore{
		project: &models.Project{
			ID: "p1", Name: "Acme", Handle: "acme",
			Platform: "hackerone", Status: models.ProjectStatusActive, UpdatedAt: now,
		},
		// All four section queries fail — page should still render with banners.
		hostsErr:     errors.New("hosts table dropped"),
		endpointsErr: errors.New("endpoints table dropped"),
		findingsErr:  errors.New("findings table dropped"),
		tasksErr:     errors.New("tasks table dropped"),
	}
	h := makeProjectDetailHandler(t, store)

	w := httptest.NewRecorder()
	h.show(w, detailRequest(http.MethodGet, "p1", true))

	require.Equal(t, http.StatusOK, w.Code,
		"all-section failure should still render the project page — only the project root is hard-required")
	body := w.Body.String()
	assert.Equal(t, 4, countSubstring(body, "banner-error"),
		"each of the four sections renders its own error banner")
	assert.NotContains(t, body, "hosts table dropped",
		"raw error must not leak — surfaces in logs only")
}

// -- single-section error doesn't poison neighbors --

func TestProjectDetail_OneSectionErrorOthersStillRender(t *testing.T) {
	now := time.Now()
	store := &fakeProjectDetailStore{
		project: &models.Project{
			ID: "p1", Name: "Acme", Handle: "acme",
			Platform: "hackerone", Status: models.ProjectStatusActive, UpdatedAt: now,
		},
		hosts: []*models.Host{
			{ID: "h1", ProjectID: "p1", Value: "api.acme.test"},
		},
		endpointsErr: errors.New("endpoints query timed out"),
		findings: []*models.Finding{
			{ID: "f1", ProjectID: "p1", Title: "Open redirect", Severity: models.SeverityMedium, Status: models.FindingStatusNew, FoundAt: now},
		},
	}
	h := makeProjectDetailHandler(t, store)

	w := httptest.NewRecorder()
	h.show(w, detailRequest(http.MethodGet, "p1", true))

	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, "api.acme.test", "hosts still render")
	assert.Contains(t, body, "Open redirect", "findings still render")
	assert.Equal(t, 1, countSubstring(body, "banner-error"),
		"only the failing section shows a banner")
}

// -- empty path param guard --

func TestProjectDetail_EmptyIDReturns404(t *testing.T) {
	h := makeProjectDetailHandler(t, &fakeProjectDetailStore{})

	w := httptest.NewRecorder()
	h.show(w, detailRequest(http.MethodGet, "", true))

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// -- helpers --

func countSubstring(s, sub string) int {
	count := 0
	for i := 0; i+len(sub) <= len(s); {
		if s[i:i+len(sub)] == sub {
			count++
			i += len(sub)
		} else {
			i++
		}
	}
	return count
}
