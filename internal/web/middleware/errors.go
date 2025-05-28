package middleware

import (
	"encoding/json"
	"net/http"
	"os"
	"runtime/debug"
	
	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// ErrorResponse represents the structure of error responses
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message"`
	Type    string                 `json:"type,omitempty"`
	Context map[string]interface{} `json:"context,omitempty"`
}

// ErrorHandler is a middleware that handles errors uniformly
func ErrorHandler(logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a custom response writer to capture errors
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}
			
			// Call the next handler
			next.ServeHTTP(rw, r)
			
			// If an error was set, handle it
			if rw.err != nil {
				handleError(w, r, rw.err, logger)
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status codes and errors
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	err        error
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// SetError sets an error to be handled by the error middleware
func SetError(w http.ResponseWriter, err error) {
	if rw, ok := w.(*responseWriter); ok {
		rw.err = err
	}
}

// handleError processes the error and sends an appropriate response
func handleError(w http.ResponseWriter, r *http.Request, err error, logger *utils.Logger) {
	if err == nil {
		return
	}
	
	// Get error details
	statusCode := pkgerrors.HTTPStatusCode(err)
	userMessage := pkgerrors.UserMessage(err)
	errorType, _ := pkgerrors.GetType(err)
	context := pkgerrors.GetContext(err)
	
	// Log the error
	if statusCode >= 500 {
		logger.Error("Internal server error: %v [%s %s] type=%s", err, r.Method, r.URL.Path, errorType)
	} else {
		logger.Warn("Client error: %v [%s %s] type=%s status=%d", err, r.Method, r.URL.Path, errorType, statusCode)
	}
	
	// Create error response
	response := ErrorResponse{
		Error:   err.Error(),
		Message: userMessage,
	}
	
	// Add type and context for non-production environments
	if !isProduction() {
		response.Type = string(errorType)
		response.Context = context
	}
	
	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error("Failed to encode error response: %v", err)
	}
}

// RecoverPanic is a middleware that recovers from panics
func RecoverPanic(logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					// Log the panic
					logger.Error("Panic recovered: %v [%s %s]", err, r.Method, r.URL.Path)
					
					// Return internal server error
					internalErr := pkgerrors.New(pkgerrors.ErrorTypeInternal, "internal server error")
					handleError(w, r, internalErr, logger)
					
					// Log stack trace in development
					if !isProduction() {
						logger.Debug("Stack trace: %s", debug.Stack())
					}
				}
			}()
			
			next.ServeHTTP(w, r)
		})
	}
}

// isProduction checks if the application is running in production
func isProduction() bool {
	env := os.Getenv("ENV")
	return env == "production" || env == "prod"
}