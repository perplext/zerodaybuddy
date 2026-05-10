package handlers

import (
	"bytes"
	"context"
	"html/template"
	"net/http"
	"sort"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// dashboardStore is the subset of storage.Store the dashboard reads. Narrow
// interface mirrors the projectStore pattern in projects.go — keeps the
// handler's surface area tiny and lets tests reuse fakeProjectStore.
type dashboardStore interface {
	ListProjects(ctx context.Context) ([]*models.Project, error)
}

// DashboardHandler serves the browser dashboard at GET /. The page lists
// every project visible to the logged-in user along with a copy-able CLI
// command panel for creating new projects (per T2-3 D5: action triggers
// are CLI commands, not POST buttons — keeps the v1 surface tiny).
//
// Auth posture: this handler sits behind OptionalAuth and self-redirects
// unauthenticated requests to /login (per T2-3 D5). It does NOT live behind
// AuthMiddleware because that would 401 instead of 303-ing — the browser
// would see a JSON error rather than the login page.
type DashboardHandler struct {
	store  dashboardStore
	tmpl   *template.Template
	logger *utils.Logger
}

// NewDashboardHandler constructs a DashboardHandler. The store argument
// accepts the full storage.Store; the handler narrows to the methods it
// uses. tmpl must include "dashboard.tmpl" — the constructor doesn't
// validate this so tests can substitute minimal templates, but production
// server.go wiring guards on tmpl.Lookup("dashboard.tmpl") != nil before
// registering.
func NewDashboardHandler(store storage.Store, tmpl *template.Template, logger *utils.Logger) *DashboardHandler {
	return &DashboardHandler{store: store, tmpl: tmpl, logger: logger}
}

// RegisterRoutes wires the dashboard onto mux at GET /{$}. The {$} pattern
// matches "/" exactly so unmatched paths still 404 instead of getting
// shadowed by a catch-all root handler.
func (h *DashboardHandler) RegisterRoutes(mux *http.ServeMux, chain []func(http.Handler) http.Handler) {
	mux.Handle("GET /{$}", middleware.Chain(http.HandlerFunc(h.index), chain...))
}

// dashboardData is the shape passed to dashboard.tmpl. Kept flat — anything
// the template needs lands here, no nested helpers in the template itself.
type dashboardData struct {
	User     *auth.User // header partial reads .User.Username
	Projects []*models.Project
	Error    string // surfaces a soft error (e.g. storage hiccup) without breaking page render
}

func (h *DashboardHandler) index(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		// OptionalAuth populated nothing → redirect to login. Use 303 so
		// browsers convert any incoming method to GET (matters if a future
		// client POSTs to /).
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	data := dashboardData{User: user}

	projects, err := h.listProjects(r.Context())
	if err != nil {
		// A storage error shouldn't blank the page — the header is still
		// useful (logout, branding). Surface the error inline instead.
		h.logger.Error("Failed to list projects for dashboard: %v", err)
		data.Error = "Could not load projects. Try again or check the server logs."
	} else {
		data.Projects = projects
	}

	h.render(w, http.StatusOK, "dashboard.tmpl", data)
}

// listProjects fetches and sorts projects for display. Sort: active first,
// then by most-recent UpdatedAt within each status bucket. This matches the
// CLI's `zerodaybuddy list-programs` output ordering so users get a
// consistent mental model across surfaces.
func (h *DashboardHandler) listProjects(ctx context.Context) ([]*models.Project, error) {
	projects, err := h.store.ListProjects(ctx)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(projects, func(i, j int) bool {
		// Status priority: active (0) < paused (1) < completed (2) < everything else (3)
		pi, pj := statusOrder(projects[i].Status), statusOrder(projects[j].Status)
		if pi != pj {
			return pi < pj
		}
		// Same status — newest UpdatedAt first.
		return projects[i].UpdatedAt.After(projects[j].UpdatedAt)
	})
	return projects, nil
}

func statusOrder(s models.ProjectStatus) int {
	switch s {
	case models.ProjectStatusActive:
		return 0
	case models.ProjectStatusCompleted:
		return 1
	case models.ProjectStatusArchived:
		return 2
	default:
		return 3
	}
}

// render writes a template to w with a prepass through a buffer so a partial
// response is never written on template-execution failure. Mirrors the
// pattern in browser_auth.go.
func (h *DashboardHandler) render(w http.ResponseWriter, status int, name string, data interface{}) {
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
