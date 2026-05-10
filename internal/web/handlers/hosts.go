package handlers

import (
	"context"
	"net/http"

	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

type hostStore interface {
	GetHost(ctx context.Context, id string) (*models.Host, error)
	ListHosts(ctx context.Context, projectID string) ([]*models.Host, error)
}

// HostsHandler exposes read-only HTTP endpoints for the Host entity.
// Hosts are created by the recon service, not by users — see plan D8.
type HostsHandler struct {
	store  hostStore
	logger *utils.Logger
}

func NewHostsHandler(store storage.Store, logger *utils.Logger) *HostsHandler {
	return &HostsHandler{store: store, logger: logger}
}

func (h *HostsHandler) RegisterRoutes(mux *http.ServeMux, authedChain []func(http.Handler) http.Handler) {
	mux.Handle("GET /api/projects/{id}/hosts", middleware.Chain(http.HandlerFunc(h.listByProject), authedChain...))
	mux.Handle("GET /api/hosts/{id}", middleware.Chain(http.HandlerFunc(h.get), authedChain...))
}

func (h *HostsHandler) listByProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	hosts, err := h.store.ListHosts(r.Context(), projectID)
	if err != nil {
		h.logger.Error("ListHosts(%s) failed: %v", projectID, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to list hosts", h.logger)
		return
	}
	if hosts == nil {
		hosts = []*models.Host{}
	}
	writeJSON(w, http.StatusOK, hosts, h.logger)
}

func (h *HostsHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	host, err := h.store.GetHost(r.Context(), id)
	if err != nil {
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, ErrCodeNotFound, "host not found", h.logger)
			return
		}
		h.logger.Error("GetHost(%s) failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to fetch host", h.logger)
		return
	}
	writeJSON(w, http.StatusOK, host, h.logger)
}

// Compile-time assertion that storage.Store satisfies hostStore.
var _ hostStore = (storage.Store)(nil)
