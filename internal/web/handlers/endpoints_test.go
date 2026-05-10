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

type fakeEndpointStore struct {
	endpoints map[string]*models.Endpoint
	listErr   error
	getErr    error
}

func (f *fakeEndpointStore) GetEndpoint(_ context.Context, id string) (*models.Endpoint, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	e, ok := f.endpoints[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return e, nil
}

func (f *fakeEndpointStore) ListEndpointsByProject(_ context.Context, projectID string) ([]*models.Endpoint, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []*models.Endpoint{}
	for _, e := range f.endpoints {
		if e.ProjectID == projectID {
			out = append(out, e)
		}
	}
	return out, nil
}

func newEndpointsHandlerWithFake(s endpointStore) *EndpointsHandler {
	return &EndpointsHandler{store: s, logger: newTestLogger()}
}

func TestEndpointsListByProject_HappyPath(t *testing.T) {
	store := &fakeEndpointStore{endpoints: map[string]*models.Endpoint{
		"e1": {ID: "e1", ProjectID: "p1", URL: "https://a/1"},
		"e2": {ID: "e2", ProjectID: "p1", URL: "https://a/2"},
		"e3": {ID: "e3", ProjectID: "other", URL: "https://b/1"},
	}}
	h := newEndpointsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/p1/endpoints", "p1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.Endpoint
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 2)
}

func TestEndpointsListByProject_NoEntriesReturnsEmptyArray(t *testing.T) {
	h := newEndpointsHandlerWithFake(&fakeEndpointStore{endpoints: map[string]*models.Endpoint{}})
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/empty/endpoints", "empty", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]\n", w.Body.String())
}

func TestEndpointsListByProject_StoreError500(t *testing.T) {
	h := newEndpointsHandlerWithFake(&fakeEndpointStore{listErr: errors.New("db down")})
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/p1/endpoints", "p1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertErrorCode(t, w, ErrCodeInternal)
}

func TestEndpointsGet_HappyPath(t *testing.T) {
	store := &fakeEndpointStore{endpoints: map[string]*models.Endpoint{
		"e1": {ID: "e1", URL: "https://a/1"},
	}}
	h := newEndpointsHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.get(w, reqWithUserCustomPath(http.MethodGet, "/api/endpoints/e1", "e1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got models.Endpoint
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "e1", got.ID)
}

func TestEndpointsGet_NotFound(t *testing.T) {
	h := newEndpointsHandlerWithFake(&fakeEndpointStore{endpoints: map[string]*models.Endpoint{}})
	w := httptest.NewRecorder()
	h.get(w, reqWithUserCustomPath(http.MethodGet, "/api/endpoints/missing", "missing", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertErrorCode(t, w, ErrCodeNotFound)
}
