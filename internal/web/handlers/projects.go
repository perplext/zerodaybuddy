package handlers

import (
	"context"
	"net/http"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/perplext/zerodaybuddy/pkg/validation"
)

// projectStore is the subset of storage.Store the projects handler uses.
// Narrowing to a small interface makes test doubles easier and documents
// the surface area touched by this handler.
type projectStore interface {
	CreateProject(ctx context.Context, project *models.Project) error
	GetProject(ctx context.Context, id string) (*models.Project, error)
	ListProjects(ctx context.Context) ([]*models.Project, error)
	DeleteProject(ctx context.Context, id string) error
}

// ProjectsHandler exposes HTTP endpoints for the Project entity.
type ProjectsHandler struct {
	store  projectStore
	logger *utils.Logger
}

// NewProjectsHandler constructs a ProjectsHandler. The store argument
// accepts the full storage.Store; the handler narrows to the methods it uses.
func NewProjectsHandler(store storage.Store, logger *utils.Logger) *ProjectsHandler {
	return &ProjectsHandler{store: store, logger: logger}
}

// RegisterRoutes wires the projects routes onto mux. All routes go through
// authedChain (authentication required); per-route role checks happen inside
// the handler methods.
func (h *ProjectsHandler) RegisterRoutes(mux *http.ServeMux, authedChain []func(http.Handler) http.Handler) {
	mux.Handle("GET /api/projects", middleware.Chain(http.HandlerFunc(h.list), authedChain...))
	mux.Handle("POST /api/projects", middleware.Chain(http.HandlerFunc(h.create), authedChain...))
	mux.Handle("GET /api/projects/{id}", middleware.Chain(http.HandlerFunc(h.get), authedChain...))
	mux.Handle("DELETE /api/projects/{id}", middleware.Chain(http.HandlerFunc(h.delete), authedChain...))
}

// createProjectRequest is the explicit allow-list of client-settable fields
// for POST /api/projects. Decoding into this struct (rather than directly
// into models.Project) prevents clients from smuggling server-set fields
// like ID, CreatedAt, or UpdatedAt.
type createProjectRequest struct {
	Name        string               `json:"name"`
	Handle      string               `json:"handle"`
	Platform    string               `json:"platform"`
	Type        models.ProjectType   `json:"type"`
	Description string               `json:"description"`
	Status      models.ProjectStatus `json:"status"`
	Scope       models.Scope         `json:"scope"`
	Notes       string               `json:"notes"`
}

func (h *ProjectsHandler) list(w http.ResponseWriter, r *http.Request) {
	projects, err := h.store.ListProjects(r.Context())
	if err != nil {
		h.logger.Error("ListProjects failed: %v", err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to list projects", h.logger)
		return
	}
	if projects == nil {
		projects = []*models.Project{}
	}
	writeJSON(w, http.StatusOK, projects, h.logger)
}

func (h *ProjectsHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	project, err := h.store.GetProject(r.Context(), id)
	if err != nil {
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, ErrCodeNotFound, "project not found", h.logger)
			return
		}
		h.logger.Error("GetProject(%s) failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to fetch project", h.logger)
		return
	}
	writeJSON(w, http.StatusOK, project, h.logger)
}

func (h *ProjectsHandler) create(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, ErrCodeUnauthorized, "authentication required", h.logger)
		return
	}
	if !user.HasPermission(auth.RoleUser) {
		writeError(w, http.StatusForbidden, ErrCodeForbidden, "user role required to create projects", h.logger)
		return
	}

	var req createProjectRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidBody, "invalid JSON body: "+err.Error(), h.logger)
		return
	}

	req.Name = validation.SanitizeString(req.Name)
	req.Handle = validation.SanitizeString(req.Handle)
	req.Description = validation.SanitizeString(req.Description)

	if err := validation.ProjectName(req.Name); err != nil {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidField, "name: "+err.Error(), h.logger)
		return
	}
	if req.Handle != "" {
		if err := validation.Handle(req.Handle); err != nil {
			writeError(w, http.StatusBadRequest, ErrCodeInvalidField, "handle: "+err.Error(), h.logger)
			return
		}
	}
	if err := validation.Platform(req.Platform); err != nil {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidField, "platform: "+err.Error(), h.logger)
		return
	}
	if req.Type != "" && !isValidProjectType(req.Type) {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidField, "type: must be one of bug-bounty, vdp, research, pentest", h.logger)
		return
	}
	if req.Status != "" && !isValidProjectStatus(req.Status) {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidField, "status: must be one of active, archived, completed", h.logger)
		return
	}

	if req.Type == "" {
		req.Type = models.ProjectTypeBugBounty
	}
	if req.Status == "" {
		req.Status = models.ProjectStatusActive
	}
	if req.Handle == "" {
		req.Handle = req.Name
	}

	project := &models.Project{
		Name:        req.Name,
		Handle:      req.Handle,
		Platform:    req.Platform,
		Type:        req.Type,
		Description: req.Description,
		StartDate:   utils.CurrentTime(),
		Status:      req.Status,
		Scope:       req.Scope,
		Notes:       req.Notes,
	}

	if err := h.store.CreateProject(r.Context(), project); err != nil {
		h.logger.Error("CreateProject failed for %s: %v", req.Name, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to create project", h.logger)
		return
	}

	writeJSON(w, http.StatusCreated, project, h.logger)
}

func (h *ProjectsHandler) delete(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, ErrCodeUnauthorized, "authentication required", h.logger)
		return
	}
	if !user.HasPermission(auth.RoleAdmin) {
		writeError(w, http.StatusForbidden, ErrCodeForbidden, "admin role required to delete projects", h.logger)
		return
	}

	id := r.PathValue("id")

	// Verify existence first so a delete on a missing id returns 404
	// rather than the silent no-op DELETE FROM gives.
	if _, err := h.store.GetProject(r.Context(), id); err != nil {
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, ErrCodeNotFound, "project not found", h.logger)
			return
		}
		h.logger.Error("GetProject(%s) before delete failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to verify project", h.logger)
		return
	}

	if err := h.store.DeleteProject(r.Context(), id); err != nil {
		h.logger.Error("DeleteProject(%s) failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to delete project", h.logger)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func isValidProjectType(t models.ProjectType) bool {
	switch t {
	case models.ProjectTypeBugBounty, models.ProjectTypeVDP, models.ProjectTypeResearch, models.ProjectTypePentest:
		return true
	}
	return false
}

func isValidProjectStatus(s models.ProjectStatus) bool {
	switch s {
	case models.ProjectStatusActive, models.ProjectStatusArchived, models.ProjectStatusCompleted:
		return true
	}
	return false
}
