package handlers

import (
	"context"
	"net/http"

	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

type endpointStore interface {
	GetEndpoint(ctx context.Context, id string) (*models.Endpoint, error)
	ListEndpointsByProject(ctx context.Context, projectID string) ([]*models.Endpoint, error)
}

// EndpointsHandler exposes read-only HTTP endpoints for the Endpoint entity.
// Per-host listing (GET /api/hosts/{id}/endpoints) is deferred to a future
// PR — list-by-project covers the dashboard use case.
type EndpointsHandler struct {
	store  endpointStore
	logger *utils.Logger
}

func NewEndpointsHandler(store storage.Store, logger *utils.Logger) *EndpointsHandler {
	return &EndpointsHandler{store: store, logger: logger}
}

func (h *EndpointsHandler) RegisterRoutes(mux *http.ServeMux, authedChain []func(http.Handler) http.Handler) {
	mux.Handle("GET /api/projects/{id}/endpoints", middleware.Chain(http.HandlerFunc(h.listByProject), authedChain...))
	mux.Handle("GET /api/endpoints/{id}", middleware.Chain(http.HandlerFunc(h.get), authedChain...))
}

func (h *EndpointsHandler) listByProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	endpoints, err := h.store.ListEndpointsByProject(r.Context(), projectID)
	if err != nil {
		h.logger.Error("ListEndpointsByProject(%s) failed: %v", projectID, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to list endpoints", h.logger)
		return
	}
	if endpoints == nil {
		endpoints = []*models.Endpoint{}
	}
	writeJSON(w, http.StatusOK, endpoints, h.logger)
}

func (h *EndpointsHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	endpoint, err := h.store.GetEndpoint(r.Context(), id)
	if err != nil {
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, ErrCodeNotFound, "endpoint not found", h.logger)
			return
		}
		h.logger.Error("GetEndpoint(%s) failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to fetch endpoint", h.logger)
		return
	}
	writeJSON(w, http.StatusOK, endpoint, h.logger)
}

var _ endpointStore = (storage.Store)(nil)
