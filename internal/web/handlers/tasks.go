package handlers

import (
	"context"
	"net/http"

	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

type taskStore interface {
	GetTask(ctx context.Context, id string) (*models.Task, error)
	ListTasks(ctx context.Context, projectID string) ([]*models.Task, error)
}

// TasksHandler exposes read-only HTTP endpoints for the Task entity.
// Tasks are recon/scan job records created by the services, not by users.
type TasksHandler struct {
	store  taskStore
	logger *utils.Logger
}

func NewTasksHandler(store storage.Store, logger *utils.Logger) *TasksHandler {
	return &TasksHandler{store: store, logger: logger}
}

func (h *TasksHandler) RegisterRoutes(mux *http.ServeMux, authedChain []func(http.Handler) http.Handler) {
	mux.Handle("GET /api/projects/{id}/tasks", middleware.Chain(http.HandlerFunc(h.listByProject), authedChain...))
	mux.Handle("GET /api/tasks/{id}", middleware.Chain(http.HandlerFunc(h.get), authedChain...))
}

func (h *TasksHandler) listByProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	tasks, err := h.store.ListTasks(r.Context(), projectID)
	if err != nil {
		h.logger.Error("ListTasks(%s) failed: %v", projectID, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to list tasks", h.logger)
		return
	}
	if tasks == nil {
		tasks = []*models.Task{}
	}
	writeJSON(w, http.StatusOK, tasks, h.logger)
}

func (h *TasksHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, err := h.store.GetTask(r.Context(), id)
	if err != nil {
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, ErrCodeNotFound, "task not found", h.logger)
			return
		}
		h.logger.Error("GetTask(%s) failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to fetch task", h.logger)
		return
	}
	writeJSON(w, http.StatusOK, task, h.logger)
}

var _ taskStore = (storage.Store)(nil)
