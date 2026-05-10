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
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeFindingStore struct {
	findings  map[string]*models.Finding
	getErr    error
	listErr   error
	updateErr error
}

func (f *fakeFindingStore) GetFinding(_ context.Context, id string) (*models.Finding, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	fd, ok := f.findings[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return fd, nil
}

func (f *fakeFindingStore) UpdateFinding(_ context.Context, finding *models.Finding) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	f.findings[finding.ID] = finding
	return nil
}

func (f *fakeFindingStore) ListFindings(_ context.Context, projectID string) ([]*models.Finding, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []*models.Finding{}
	for _, fd := range f.findings {
		if fd.ProjectID == projectID {
			out = append(out, fd)
		}
	}
	return out, nil
}

func newFindingsHandlerWithFake(s findingStore) *FindingsHandler {
	return &FindingsHandler{store: s, logger: newTestLogger()}
}

func patchReq(target, idValue string, body []byte, user *auth.User) *http.Request {
	r := httptest.NewRequest(http.MethodPatch, target, bytes.NewReader(body))
	if user != nil {
		r = r.WithContext(contextWithUserForTest(r.Context(), user))
	}
	r.SetPathValue("id", idValue)
	return r
}

// -- LIST / GET --

func TestFindingsListByProject_HappyPath(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{
		"f1": {ID: "f1", ProjectID: "p1", Title: "XSS"},
		"f2": {ID: "f2", ProjectID: "p1", Title: "SQLi"},
		"f3": {ID: "f3", ProjectID: "other", Title: "elsewhere"},
	}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/p1/findings", "p1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 2)
}

func TestFindingsListByProject_StoreError500(t *testing.T) {
	h := newFindingsHandlerWithFake(&fakeFindingStore{listErr: errors.New("db down")})
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/p1/findings", "p1", userOf(auth.RoleReadOnly)))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertErrorCode(t, w, ErrCodeInternal)
}

func TestFindingsGet_HappyPath(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{
		"f1": {ID: "f1", Title: "XSS", Status: models.FindingStatusNew, Severity: models.SeverityMedium},
	}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.get(w, reqWithUserCustomPath(http.MethodGet, "/api/findings/f1", "f1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got models.Finding
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "f1", got.ID)
}

func TestFindingsGet_NotFound(t *testing.T) {
	h := newFindingsHandlerWithFake(&fakeFindingStore{findings: map[string]*models.Finding{}})
	w := httptest.NewRecorder()
	h.get(w, reqWithUserCustomPath(http.MethodGet, "/api/findings/missing", "missing", userOf(auth.RoleReadOnly)))
	assert.Equal(t, http.StatusNotFound, w.Code)
	assertErrorCode(t, w, ErrCodeNotFound)
}

// -- PATCH happy paths --

func TestFindingsPatch_StatusOnly(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{
		"f1": {ID: "f1", Status: models.FindingStatusNew, Severity: models.SeverityMedium},
	}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{"status":"confirmed"}`), userOf(auth.RoleUser)))

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	assert.Equal(t, models.FindingStatusConfirmed, store.findings["f1"].Status)
	assert.Equal(t, models.SeverityMedium, store.findings["f1"].Severity, "severity unchanged when not in patch")
}

func TestFindingsPatch_SeverityOnly(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{
		"f1": {ID: "f1", Status: models.FindingStatusNew, Severity: models.SeverityMedium},
	}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{"severity":"high"}`), userOf(auth.RoleUser)))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, models.SeverityHigh, store.findings["f1"].Severity)
	assert.Equal(t, models.FindingStatusNew, store.findings["f1"].Status)
}

func TestFindingsPatch_BothFieldsAtomically(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{
		"f1": {ID: "f1", Status: models.FindingStatusNew, Severity: models.SeverityMedium},
	}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{"status":"resolved","severity":"low"}`), userOf(auth.RoleUser)))

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, models.FindingStatusResolved, store.findings["f1"].Status)
	assert.Equal(t, models.SeverityLow, store.findings["f1"].Severity)
}

// -- PATCH allow-list rejection --

func TestFindingsPatch_EmptyBody_400(t *testing.T) {
	h := newFindingsHandlerWithFake(&fakeFindingStore{findings: map[string]*models.Finding{}})
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{}`), userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidBody)
}

func TestFindingsPatch_OnlyIgnoredFields_400(t *testing.T) {
	// Client sends a field that's not in the allow-list. The decode silently
	// drops it (encoding/json default), then the handler rejects because no
	// allowed fields were set.
	store := &fakeFindingStore{findings: map[string]*models.Finding{
		"f1": {ID: "f1", Title: "original", Status: models.FindingStatusNew},
	}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{"title":"hijacked"}`), userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidBody)
	assert.Equal(t, "original", store.findings["f1"].Title, "title must NOT be patchable; allow-list must hold")
}

// -- PATCH validation --

func TestFindingsPatch_InvalidStatus_400(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{"f1": {ID: "f1"}}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{"status":"nonsense"}`), userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidField)
}

func TestFindingsPatch_InvalidSeverity_400(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{"f1": {ID: "f1"}}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{"severity":"nuclear"}`), userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidField)
}

func TestFindingsPatch_NotFound(t *testing.T) {
	h := newFindingsHandlerWithFake(&fakeFindingStore{findings: map[string]*models.Finding{}})
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/missing", "missing", []byte(`{"status":"resolved"}`), userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertErrorCode(t, w, ErrCodeNotFound)
}

// -- PATCH role and auth checks --

func TestFindingsPatch_AsReadonly_Forbidden(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{"f1": {ID: "f1"}}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{"status":"resolved"}`), userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusForbidden, w.Code)
	assertErrorCode(t, w, ErrCodeForbidden)
}

func TestFindingsPatch_NoUser_Unauthorized(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{"f1": {ID: "f1"}}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{"status":"resolved"}`), nil))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assertErrorCode(t, w, ErrCodeUnauthorized)
}

func TestFindingsPatch_InvalidJSON_400(t *testing.T) {
	store := &fakeFindingStore{findings: map[string]*models.Finding{"f1": {ID: "f1"}}}
	h := newFindingsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.patch(w, patchReq("/api/findings/f1", "f1", []byte(`{not json}`), userOf(auth.RoleUser)))

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assertErrorCode(t, w, ErrCodeInvalidBody)
}
