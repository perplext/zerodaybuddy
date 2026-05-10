package handlers

import (
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

type fakeHostStore struct {
	hosts   map[string]*models.Host
	listErr error
	getErr  error
}

func (f *fakeHostStore) GetHost(_ context.Context, id string) (*models.Host, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	h, ok := f.hosts[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return h, nil
}

func (f *fakeHostStore) ListHosts(_ context.Context, projectID string) ([]*models.Host, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []*models.Host{}
	for _, h := range f.hosts {
		if h.ProjectID == projectID {
			out = append(out, h)
		}
	}
	return out, nil
}

func newHostsHandlerWithFake(s hostStore) *HostsHandler {
	return &HostsHandler{store: s, logger: newTestLogger()}
}

// reqWithUserCustomPath is like reqWithUser but lets the caller specify the
// PathValue("id") explicitly — the auto-extraction in projects_test.go assumes
// /api/projects/{id}; for /api/projects/{pid}/hosts and /api/hosts/{id} we
// want explicit control.
func reqWithUserCustomPath(method, target, idValue string, user *auth.User) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	if user != nil {
		r = r.WithContext(useUser(r.Context(), user))
	}
	r.SetPathValue("id", idValue)
	return r
}

// useUser is a thin wrapper so tests don't need to import middleware here.
// (The tests for projects do import middleware; here we keep the dependency
// surface tighter for the read-only handler test files.)
func useUser(ctx context.Context, u *auth.User) context.Context {
	return contextWithUserForTest(ctx, u)
}

func TestHostsListByProject_HappyPath(t *testing.T) {
	store := &fakeHostStore{hosts: map[string]*models.Host{
		"h1": {ID: "h1", ProjectID: "p1", Value: "a.example.com"},
		"h2": {ID: "h2", ProjectID: "p1", Value: "b.example.com"},
		"h3": {ID: "h3", ProjectID: "p-other", Value: "c.example.com"},
	}}
	h := newHostsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/p1/hosts", "p1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.Host
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 2, "only hosts for p1 should be returned, not p-other")
}

func TestHostsListByProject_NoEntriesReturnsEmptyArray(t *testing.T) {
	h := newHostsHandlerWithFake(&fakeHostStore{hosts: map[string]*models.Host{}})
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/empty/hosts", "empty", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]\n", w.Body.String())
}

func TestHostsListByProject_StoreError500(t *testing.T) {
	h := newHostsHandlerWithFake(&fakeHostStore{listErr: errors.New("db down")})
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/p1/hosts", "p1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertErrorCode(t, w, ErrCodeInternal)
}

func TestHostsGet_HappyPath(t *testing.T) {
	store := &fakeHostStore{hosts: map[string]*models.Host{
		"h1": {ID: "h1", Value: "a.example.com"},
	}}
	h := newHostsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.get(w, reqWithUserCustomPath(http.MethodGet, "/api/hosts/h1", "h1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got models.Host
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "h1", got.ID)
}

func TestHostsGet_NotFound(t *testing.T) {
	h := newHostsHandlerWithFake(&fakeHostStore{hosts: map[string]*models.Host{}})
	w := httptest.NewRecorder()
	h.get(w, reqWithUserCustomPath(http.MethodGet, "/api/hosts/missing", "missing", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertErrorCode(t, w, ErrCodeNotFound)
}
