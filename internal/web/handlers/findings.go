package handlers

import (
	"context"
	"net/http"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/models"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

type findingStore interface {
	GetFinding(ctx context.Context, id string) (*models.Finding, error)
	UpdateFinding(ctx context.Context, finding *models.Finding) error
	ListFindings(ctx context.Context, projectID string) ([]*models.Finding, error)
}

// FindingsHandler exposes HTTP endpoints for the Finding entity:
// list-by-project, get-by-id, and PATCH for status / severity.
type FindingsHandler struct {
	store  findingStore
	logger *utils.Logger
}

func NewFindingsHandler(store storage.Store, logger *utils.Logger) *FindingsHandler {
	return &FindingsHandler{store: store, logger: logger}
}

func (h *FindingsHandler) RegisterRoutes(mux *http.ServeMux, authedChain []func(http.Handler) http.Handler) {
	mux.Handle("GET /api/projects/{id}/findings", middleware.Chain(http.HandlerFunc(h.listByProject), authedChain...))
	mux.Handle("GET /api/findings/{id}", middleware.Chain(http.HandlerFunc(h.get), authedChain...))
	mux.Handle("PATCH /api/findings/{id}", middleware.Chain(http.HandlerFunc(h.patch), authedChain...))
}

// patchFindingRequest is the explicit allow-list for PATCH /api/findings/{id}.
// Pointer fields distinguish "not set in request" (nil) from "set to empty"
// (non-nil pointer to zero value). Adding a new mutable field requires:
//
//  1. adding a pointer field here
//  2. validating it in patch()
//  3. applying it to the loaded finding in patch()
type patchFindingRequest struct {
	Status   *models.FindingStatus   `json:"status,omitempty"`
	Severity *models.FindingSeverity `json:"severity,omitempty"`
}

func (h *FindingsHandler) listByProject(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	findings, err := h.store.ListFindings(r.Context(), projectID)
	if err != nil {
		h.logger.Error("ListFindings(%s) failed: %v", projectID, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to list findings", h.logger)
		return
	}
	if findings == nil {
		findings = []*models.Finding{}
	}
	writeJSON(w, http.StatusOK, findings, h.logger)
}

func (h *FindingsHandler) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	finding, err := h.store.GetFinding(r.Context(), id)
	if err != nil {
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, ErrCodeNotFound, "finding not found", h.logger)
			return
		}
		h.logger.Error("GetFinding(%s) failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to fetch finding", h.logger)
		return
	}
	writeJSON(w, http.StatusOK, finding, h.logger)
}

func (h *FindingsHandler) patch(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, ErrCodeUnauthorized, "authentication required", h.logger)
		return
	}
	if !user.HasPermission(auth.RoleUser) {
		writeError(w, http.StatusForbidden, ErrCodeForbidden, "user role required to update findings", h.logger)
		return
	}

	id := r.PathValue("id")

	var req patchFindingRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidBody, "invalid JSON body: "+err.Error(), h.logger)
		return
	}

	// Reject requests that contain no allow-listed fields. This catches both
	// the empty-body case and the case where the client sent only ignored
	// fields (e.g., {"title": "..."} — title is not patchable here).
	if req.Status == nil && req.Severity == nil {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidBody, "no allowed fields to update; valid fields: status, severity", h.logger)
		return
	}

	// Validate enum values before fetching — fail fast on bad input.
	if req.Status != nil && !isValidFindingStatus(*req.Status) {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidField, "status: must be one of new, confirmed, duplicate, false_positive, reported, resolved", h.logger)
		return
	}
	if req.Severity != nil && !isValidFindingSeverity(*req.Severity) {
		writeError(w, http.StatusBadRequest, ErrCodeInvalidField, "severity: must be one of critical, high, medium, low, info", h.logger)
		return
	}

	// Load existing finding (also gives us 404 for missing id).
	finding, err := h.store.GetFinding(r.Context(), id)
	if err != nil {
		if isNotFoundErr(err) {
			writeError(w, http.StatusNotFound, ErrCodeNotFound, "finding not found", h.logger)
			return
		}
		h.logger.Error("GetFinding(%s) before patch failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to fetch finding", h.logger)
		return
	}

	// Apply allow-listed updates.
	if req.Status != nil {
		finding.Status = *req.Status
	}
	if req.Severity != nil {
		finding.Severity = *req.Severity
	}

	if err := h.store.UpdateFinding(r.Context(), finding); err != nil {
		h.logger.Error("UpdateFinding(%s) failed: %v", id, err)
		writeError(w, http.StatusInternalServerError, ErrCodeInternal, "failed to update finding", h.logger)
		return
	}

	writeJSON(w, http.StatusOK, finding, h.logger)
}

func isValidFindingStatus(s models.FindingStatus) bool {
	switch s {
	case models.FindingStatusNew,
		models.FindingStatusConfirmed,
		models.FindingStatusDuplicate,
		models.FindingStatusFalsePositive,
		models.FindingStatusReported,
		models.FindingStatusResolved:
		return true
	}
	return false
}

func isValidFindingSeverity(s models.FindingSeverity) bool {
	switch s {
	case models.SeverityCritical,
		models.SeverityHigh,
		models.SeverityMedium,
		models.SeverityLow,
		models.SeverityInfo:
		return true
	}
	return false
}

var _ findingStore = (storage.Store)(nil)
