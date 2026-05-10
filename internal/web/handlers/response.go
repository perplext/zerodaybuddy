package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/perplext/zerodaybuddy/internal/storage"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// isNotFoundErr returns true for both storage.ErrNotFound and the raw
// sql.ErrNoRows. The storage layer does not consistently translate the
// driver-level sentinel to storage.ErrNotFound (see the in-progress
// errors_impl.go refactor); handlers must accept either.
func isNotFoundErr(err error) bool {
	return errors.Is(err, storage.ErrNotFound) || errors.Is(err, sql.ErrNoRows)
}

// ErrorResponse is the wire format for API error responses. Wrapping the
// error in a top-level "error" key gives clients a stable shape they can
// switch on regardless of the underlying HTTP status code.
type ErrorResponse struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail carries the structured pieces of an error response.
// Code is a stable, machine-readable identifier ("not_found", "forbidden",
// etc.). Message is human-readable.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Standard error codes used across data-model handlers. Adding a new code
// here is preferable to inventing one inline at the call site — it keeps the
// client-facing vocabulary tractable.
const (
	ErrCodeNotFound     = "not_found"
	ErrCodeForbidden    = "forbidden"
	ErrCodeUnauthorized = "unauthorized"
	ErrCodeInvalidBody  = "invalid_body"
	ErrCodeInvalidField = "invalid_field"
	ErrCodeConflict     = "conflict"
	ErrCodeInternal     = "internal"
)

// writeJSON encodes v as JSON and writes it to w with the given status code.
// Sets Content-Type and calls WriteHeader before encoding. If encoding fails
// after the header is sent there is nothing to recover; logs the error and
// returns. Callers should treat writeJSON as terminal — no further writes
// to w should happen after it returns.
func writeJSON(w http.ResponseWriter, status int, v any, logger *utils.Logger) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		logger.Error("Failed to encode JSON response: %v", err)
	}
}

// writeError sends a structured error envelope as JSON. Equivalent to
// writeJSON(w, status, ErrorResponse{Error: ErrorDetail{Code: code, Message: msg}}, logger).
func writeError(w http.ResponseWriter, status int, code, msg string, logger *utils.Logger) {
	writeJSON(w, status, ErrorResponse{Error: ErrorDetail{Code: code, Message: msg}}, logger)
}

// decodeJSON parses r.Body into v. Returns the raw decoder error so callers
// can choose between writeError(400, "invalid_body", err.Error()) for client
// errors and writeError(500, "internal", "...") for genuine bugs.
//
// Body size is bounded by the MaxBodySize middleware applied at the router
// level; decodeJSON does not enforce its own limit. Unknown fields in the
// JSON are silently ignored (the default encoding/json behavior) — this
// preserves forward-compatibility for clients sending fields the server
// doesn't yet recognise.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
