package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProjectStore is an in-memory test double satisfying the projectStore
// interface. Real-storage integration is exercised in router_test.go (U6);
// these tests focus on handler logic in isolation.
type fakeProjectStore struct {
	projects   map[string]*models.Project
	createErr  error
	getErr     error
	listErr    error
	deleteErr  error
	createHook func(*models.Project)
}

func newFakeStore() *fakeProjectStore {
	return &fakeProjectStore{projects: make(map[string]*models.Project)}
}

func (f *fakeProjectStore) CreateProject(ctx context.Context, p *models.Project) error {
	if f.createErr != nil {
		return f.createErr
	}
	if p.ID == "" {
		p.ID = "fake-id-" + p.Name
	}
	if f.createHook != nil {
		f.createHook(p)
	}
	f.projects[p.ID] = p
	return nil
}

func (f *fakeProjectStore) GetProject(ctx context.Context, id string) (*models.Project, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	p, ok := f.projects[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return p, nil
}

func (f *fakeProjectStore) ListProjects(ctx context.Context) ([]*models.Project, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]*models.Project, 0, len(f.projects))
	for _, p := range f.projects {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeProjectStore) DeleteProject(ctx context.Context, id string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.projects, id)
	return nil
}

// newProjectsHandlerWithFake constructs a ProjectsHandler with an in-memory
// fake. Bypasses the storage.Store coupling in NewProjectsHandler — direct
// struct construction is fine because the production constructor is just
// field assignment.
func newProjectsHandlerWithFake(store projectStore) *ProjectsHandler {
	return &ProjectsHandler{store: store, logger: newTestLogger()}
}

func reqWithUser(method, target string, body []byte, user *auth.User) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	if user != nil {
		r = r.WithContext(middleware.ContextWithUser(r.Context(), user))
	}
	// Inject a fake "id" path value so PathValue("id") works without going
	// through the mux. ServeMux normally populates this; tests that bypass
	// the mux must set it manually.
	if id := extractIDFromPath(target); id != "" {
		r.SetPathValue("id", id)
	}
	return r
}

// extractIDFromPath pulls the last path segment when the URL ends in
// /api/projects/{id} so tests can set PathValue without hardcoding it.
func extractIDFromPath(target string) string {
	const prefix = "/api/projects/"
	if len(target) <= len(prefix) {
		return ""
	}
	return target[len(prefix):]
}

func userOf(role auth.UserRole) *auth.User {
	return &auth.User{ID: "u1", Username: "alice", Role: role, Status: auth.StatusActive}
}

// -- LIST --

func TestProjectsList_EmptyReturnsEmptyArray(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	w := httptest.NewRecorder()
	h.list(w, reqWithUser(http.MethodGet, "/api/projects", nil, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]\n", w.Body.String(), "empty list must serialize as JSON array, not null")
}

func TestProjectsList_NonEmpty(t *testing.T) {
	store := newFakeStore()
	store.projects["a"] = &models.Project{ID: "a", Name: "Alpha"}
	store.projects["b"] = &models.Project{ID: "b", Name: "Beta"}

	h := newProjectsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.list(w, reqWithUser(http.MethodGet, "/api/projects", nil, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.Project
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 2)
}

func TestProjectsList_StoreError500(t *testing.T) {
	store := newFakeStore()
	store.listErr = errors.New("boom")
	h := newProjectsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.list(w, reqWithUser(http.MethodGet, "/api/projects", nil, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertErrorCode(t, w, ErrCodeInternal)
}

// -- GET --

func TestProjectsGet_HappyPath(t *testing.T) {
	store := newFakeStore()
	store.projects["abc"] = &models.Project{ID: "abc", Name: "Alpha"}
	h := newProjectsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.get(w, reqWithUser(http.MethodGet, "/api/projects/abc", nil, userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got models.Project
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "abc", got.ID)
}

func TestProjectsGet_NotFound(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	w := httptest.NewRecorder()
	h.get(w, reqWithUser(http.MethodGet, "/api/projects/missing", nil, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertErrorCode(t, w, ErrCodeNotFound)
}

// -- CREATE --

func TestProjectsCreate_HappyPath(t *testing.T) {
	store := newFakeStore()
	h := newProjectsHandlerWithFake(store)

	body := mustJSON(t, map[string]any{
		"name":     "test-project",
		"platform": "hackerone", // non-manual: exercises the bug-bounty default path
	})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	var got models.Project
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.NotEmpty(t, got.ID, "store should assign an ID via the fake")
	assert.Equal(t, "test-project", got.Name)
	assert.Equal(t, models.ProjectTypeBugBounty, got.Type, "default type when omitted")
	assert.Equal(t, models.ProjectStatusActive, got.Status, "default status when omitted")
	assert.Equal(t, "test-project", got.Handle, "handle defaults to name when omitted")
}

func TestProjectsCreate_DefaultsApplied(t *testing.T) {
	store := newFakeStore()
	h := newProjectsHandlerWithFake(store)
	body := mustJSON(t, map[string]any{
		"name":     "p1",
		"handle":   "p1",
		"platform": "hackerone", // non-manual: explicit type/status override path
		"type":     "vdp",
		"status":   "archived",
	})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	require.Equal(t, http.StatusCreated, w.Code)
	var got models.Project
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, models.ProjectTypeVDP, got.Type)
	assert.Equal(t, models.ProjectStatusArchived, got.Status)
}

func TestProjectsCreate_AsAdminAllowed(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, map[string]any{"name": "admincreate", "platform": "hackerone"})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleAdmin)))

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestProjectsCreate_AsReadonlyForbidden(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, map[string]any{"name": "x", "platform": "manual"})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assertErrorCode(t, w, ErrCodeForbidden)
}

func TestProjectsCreate_NoUserContext_Unauthorized(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, map[string]any{"name": "x", "platform": "manual"})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, nil))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assertErrorCode(t, w, ErrCodeUnauthorized)
}

func TestProjectsCreate_InvalidJSON_400(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/projects", bytes.NewReader([]byte(`{not valid`)))
	r = r.WithContext(middleware.ContextWithUser(r.Context(), userOf(auth.RoleUser)))
	h.create(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidBody)
}

func TestProjectsCreate_EmptyName_400(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, map[string]any{"name": "", "platform": "manual"})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidField)
}

func TestProjectsCreate_InvalidPlatform_400(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, map[string]any{"name": "ok", "platform": "yahoo"})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidField)
}

func TestProjectsCreate_InvalidType_400(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, map[string]any{"name": "ok", "platform": "manual", "type": "nonsense"})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidField)
}

func TestProjectsCreate_ClientCannotSmuggleServerSetFields(t *testing.T) {
	// Security check from the plan: client sends an `id` and `created_at`;
	// server must IGNORE them, not use them. The decode-into-request-struct
	// pattern means these fields aren't even in createProjectRequest, so they
	// silently drop.
	store := newFakeStore()
	h := newProjectsHandlerWithFake(store)

	body := mustJSON(t, map[string]any{
		"name":       "clean",
		"platform":   "hackerone",
		"id":         "client-supplied-id",
		"created_at": "1970-01-01T00:00:00Z",
	})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	require.Equal(t, http.StatusCreated, w.Code)
	var got models.Project
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.NotEqual(t, "client-supplied-id", got.ID,
		"client-supplied id MUST NOT propagate; the storage layer assigns one")
}

// -- CREATE: manual mode / scope validation (U4) --

func validScopeBody(name, platform string) map[string]any {
	return map[string]any{
		"name":     name,
		"platform": platform,
		"scope": map[string]any{
			"in_scope": []map[string]any{
				{"type": "domain", "value": "example.com"},
				{"type": "domain", "value": "*.example.com"},
			},
		},
	}
}

func TestProjectsCreate_ManualHappyPath(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, validScopeBody("manual-web", "manual"))
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	var got models.Project
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, models.PlatformManual, got.Platform)
	assert.Equal(t, models.ProjectTypeResearch, got.Type, "manual default type is research, not bug-bounty")
	assert.Len(t, got.Scope.InScope, 2)
}

// TestProjectsCreate_ManualMatchesCLIDefault locks the CLI/web parity the plan
// requires: a manual project created via the web gets the same default Type the
// CLI helper assigns (research), because both route through NewManualProject.
func TestProjectsCreate_ManualMatchesCLIDefault(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, validScopeBody("parity", "manual"))
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))
	require.Equal(t, http.StatusCreated, w.Code)

	cliProject, err := models.NewManualProject("parity", "", "", models.Scope{
		InScope: []models.Asset{{Type: models.AssetTypeDomain, Value: "example.com"}},
	})
	require.NoError(t, err)

	var webProject models.Project
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &webProject))
	assert.Equal(t, cliProject.Type, webProject.Type, "web and CLI manual defaults must match")
	assert.Equal(t, cliProject.Platform, webProject.Platform)
}

func TestProjectsCreate_ManualInvalidScopeType_400(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, map[string]any{
		"name":     "bad-scope",
		"platform": "manual",
		"scope": map[string]any{
			"in_scope": []map[string]any{{"type": "web", "value": "example.com"}},
		},
	})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidField)
}

func TestProjectsCreate_ManualEmptyScope_400(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	body := mustJSON(t, map[string]any{"name": "no-scope", "platform": "manual"})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidField)
}

// TestProjectsCreate_ScopeValidatedRegardlessOfPlatform closes the bypass the
// security review flagged: a non-manual platform with an invalid inline scope
// must still be rejected, not silently persisted.
func TestProjectsCreate_ScopeValidatedRegardlessOfPlatform(t *testing.T) {
	store := newFakeStore()
	h := newProjectsHandlerWithFake(store)
	body := mustJSON(t, map[string]any{
		"name":     "sneaky",
		"platform": "hackerone",
		"scope": map[string]any{
			"in_scope": []map[string]any{{"type": "web", "value": "x"}},
		},
	})
	w := httptest.NewRecorder()
	h.create(w, reqWithUser(http.MethodPost, "/api/projects", body, userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code, "invalid scope must be rejected even when platform != manual")
	assert.Empty(t, store.projects, "nothing should be persisted")
}

// -- DELETE --

func TestProjectsDelete_AdminSucceeds(t *testing.T) {
	store := newFakeStore()
	store.projects["x"] = &models.Project{ID: "x", Name: "x"}
	h := newProjectsHandlerWithFake(store)

	w := httptest.NewRecorder()
	h.delete(w, reqWithUser(http.MethodDelete, "/api/projects/x", nil, userOf(auth.RoleAdmin)))

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.String(), "204 must have empty body")
	_, exists := store.projects["x"]
	assert.False(t, exists, "project should be removed from store")
}

func TestProjectsDelete_NonAdminForbidden(t *testing.T) {
	store := newFakeStore()
	store.projects["x"] = &models.Project{ID: "x"}
	h := newProjectsHandlerWithFake(store)

	for _, role := range []auth.UserRole{auth.RoleUser, auth.RoleReadOnly} {
		t.Run(string(role), func(t *testing.T) {
			w := httptest.NewRecorder()
			h.delete(w, reqWithUser(http.MethodDelete, "/api/projects/x", nil, userOf(role)))
			assert.Equal(t, http.StatusForbidden, w.Code)
			assertErrorCode(t, w, ErrCodeForbidden)
		})
	}
	// Project should still exist after both forbidden attempts.
	_, exists := store.projects["x"]
	assert.True(t, exists)
}

func TestProjectsDelete_NotFound(t *testing.T) {
	h := newProjectsHandlerWithFake(newFakeStore())
	w := httptest.NewRecorder()
	h.delete(w, reqWithUser(http.MethodDelete, "/api/projects/missing", nil, userOf(auth.RoleAdmin)))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertErrorCode(t, w, ErrCodeNotFound)
}

// -- helpers shared with other handler tests --

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, code string) {
	t.Helper()
	var got ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got),
		"body should be a structured ErrorResponse, got: %s", w.Body.String())
	assert.Equal(t, code, got.Error.Code)
}
