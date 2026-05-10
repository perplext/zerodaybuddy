package handlers

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"net/http"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// projectDetailStore narrows storage.Store to the methods the project detail
// page reads. Same pattern as projectStore / dashboardStore.
//
// The five queries fire serially, per T2-3 plan D6: in-process SQLite makes
// this acceptable for v1. If this page ever moves behind a network boundary,
// a single GetProjectWithRelations would replace the fan-out cleanly.
type projectDetailStore interface {
	GetProject(ctx context.Context, id string) (*models.Project, error)
	ListHosts(ctx context.Context, projectID string) ([]*models.Host, error)
	ListEndpointsByProject(ctx context.Context, projectID string) ([]*models.Endpoint, error)
	ListFindings(ctx context.Context, projectID string) ([]*models.Finding, error)
	ListTasks(ctx context.Context, projectID string) ([]*models.Task, error)
}

// ProjectDetailHandler serves GET /projects/{id} — the per-project page
// showing hosts, endpoints, findings, and tasks plus three CLI command
// panels (recon, scan, report) that link the UI back to the CLI per
// T2-3 D5.
type ProjectDetailHandler struct {
	store  projectDetailStore
	tmpl   *template.Template
	logger *utils.Logger
}

// NewProjectDetailHandler constructs a ProjectDetailHandler. Same store-
// narrowing pattern as ProjectsHandler — accepts the full storage.Store and
// pins down the method surface internally.
func NewProjectDetailHandler(store storage.Store, tmpl *template.Template, logger *utils.Logger) *ProjectDetailHandler {
	return &ProjectDetailHandler{store: store, tmpl: tmpl, logger: logger}
}

// RegisterRoutes wires GET /projects/{id} onto mux.
func (h *ProjectDetailHandler) RegisterRoutes(mux *http.ServeMux, chain []func(http.Handler) http.Handler) {
	mux.Handle("GET /projects/{id}", middleware.Chain(http.HandlerFunc(h.show), chain...))
}

// projectDetailData is the template-side shape. Sections each carry their
// own slice; an empty slice renders as a "no items yet" empty-state row in
// the template rather than hiding the section.
type projectDetailData struct {
	User      *auth.User
	Project   *models.Project
	Hosts     []*models.Host
	Endpoints []*models.Endpoint
	Findings  []*models.Finding
	Tasks     []*models.Task
	// Soft errors per section — non-empty means "this section couldn't load,
	// surface it inline but still render the rest of the page". Mirrors the
	// dashboard's posture: never fail the whole page over one storage hiccup.
	HostsErr     string
	EndpointsErr string
	FindingsErr  string
	TasksErr     string
}

func (h *ProjectDetailHandler) show(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	projectID := r.PathValue("id")
	if projectID == "" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()
	project, err := h.store.GetProject(ctx, projectID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		h.logger.Error("Failed to load project %s: %v", projectID, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := projectDetailData{User: user, Project: project}

	// Per-section soft errors — losing one section shouldn't blank the page.
	if hosts, err := h.store.ListHosts(ctx, projectID); err != nil {
		h.logger.Error("Failed to list hosts for %s: %v", projectID, err)
		data.HostsErr = "Could not load hosts."
	} else {
		data.Hosts = hosts
	}

	if endpoints, err := h.store.ListEndpointsByProject(ctx, projectID); err != nil {
		h.logger.Error("Failed to list endpoints for %s: %v", projectID, err)
		data.EndpointsErr = "Could not load endpoints."
	} else {
		data.Endpoints = endpoints
	}

	if findings, err := h.store.ListFindings(ctx, projectID); err != nil {
		h.logger.Error("Failed to list findings for %s: %v", projectID, err)
		data.FindingsErr = "Could not load findings."
	} else {
		data.Findings = findings
	}

	if tasks, err := h.store.ListTasks(ctx, projectID); err != nil {
		h.logger.Error("Failed to list tasks for %s: %v", projectID, err)
		data.TasksErr = "Could not load tasks."
	} else {
		data.Tasks = tasks
	}

	h.render(w, http.StatusOK, "project_detail.tmpl", data)
}

func (h *ProjectDetailHandler) render(w http.ResponseWriter, status int, name string, data interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		h.logger.Error("Failed to render template %s: %v", name, err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if _, err := w.Write(buf.Bytes()); err != nil {
		h.logger.Error("Failed to write response: %v", err)
	}
}
