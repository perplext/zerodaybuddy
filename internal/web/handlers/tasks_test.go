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

type fakeTaskStore struct {
	tasks   map[string]*models.Task
	listErr error
	getErr  error
}

func (f *fakeTaskStore) GetTask(_ context.Context, id string) (*models.Task, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	tk, ok := f.tasks[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return tk, nil
}

func (f *fakeTaskStore) ListTasks(_ context.Context, projectID string) ([]*models.Task, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := []*models.Task{}
	for _, tk := range f.tasks {
		if tk.ProjectID == projectID {
			out = append(out, tk)
		}
	}
	return out, nil
}

func newTasksHandlerWithFake(s taskStore) *TasksHandler {
	return &TasksHandler{store: s, logger: newTestLogger()}
}

func TestTasksListByProject_HappyPath(t *testing.T) {
	store := &fakeTaskStore{tasks: map[string]*models.Task{
		"t1": {ID: "t1", ProjectID: "p1", Type: "recon"},
		"t2": {ID: "t2", ProjectID: "p1", Type: "scan"},
		"t3": {ID: "t3", ProjectID: "other", Type: "recon"},
	}}
	h := newTasksHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/p1/tasks", "p1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.Task
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 2)
}

func TestTasksListByProject_NoEntriesReturnsEmptyArray(t *testing.T) {
	h := newTasksHandlerWithFake(&fakeTaskStore{tasks: map[string]*models.Task{}})
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/empty/tasks", "empty", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "[]\n", w.Body.String())
}

func TestTasksListByProject_StoreError500(t *testing.T) {
	h := newTasksHandlerWithFake(&fakeTaskStore{listErr: errors.New("db down")})
	w := httptest.NewRecorder()
	h.listByProject(w, reqWithUserCustomPath(http.MethodGet, "/api/projects/p1/tasks", "p1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assertErrorCode(t, w, ErrCodeInternal)
}

func TestTasksGet_HappyPath(t *testing.T) {
	store := &fakeTaskStore{tasks: map[string]*models.Task{
		"t1": {ID: "t1", Type: "recon"},
	}}
	h := newTasksHandlerWithFake(store)
	w := httptest.NewRecorder()
	h.get(w, reqWithUserCustomPath(http.MethodGet, "/api/tasks/t1", "t1", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusOK, w.Code)
	var got models.Task
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Equal(t, "t1", got.ID)
}

func TestTasksGet_NotFound(t *testing.T) {
	h := newTasksHandlerWithFake(&fakeTaskStore{tasks: map[string]*models.Task{}})
	w := httptest.NewRecorder()
	h.get(w, reqWithUserCustomPath(http.MethodGet, "/api/tasks/missing", "missing", userOf(auth.RoleReadOnly)))

	assert.Equal(t, http.StatusNotFound, w.Code)
	assertErrorCode(t, w, ErrCodeNotFound)
}
