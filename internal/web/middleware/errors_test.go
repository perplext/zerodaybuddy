package middleware

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorHandler(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedStatus int
		expectedError  bool
		checkResponse  func(t *testing.T, resp ErrorResponse)
	}{
		{
			name: "successful request - no error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			},
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name: "handler sets error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				SetError(w, errors.New("test error"))
				w.WriteHeader(http.StatusBadRequest)
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  false, // Error is captured but not handled in this simplified test
		},
		{
			name: "handler continues normally after error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				w.Write([]byte("created"))
			},
			expectedStatus: http.StatusCreated,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply middleware
			middleware := ErrorHandler(logger)
			wrappedHandler := middleware(tt.handler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			// Execute request
			wrappedHandler.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
		})
	}
}

func TestHandleError(t *testing.T) {
	logger := utils.NewLogger("", false)

	// Save original ENV
	originalEnv := os.Getenv("ENV")
	defer os.Setenv("ENV", originalEnv)

	tests := []struct {
		name             string
		err              error
		env              string
		expectedStatus   int
		expectedResponse ErrorResponse
		checkResponse    func(t *testing.T, resp ErrorResponse)
	}{
		{
			name:           "nil error",
			err:            nil,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "validation error",
			err:            pkgerrors.ValidationError("invalid input"),
			env:            "development",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "invalid input")
				assert.Equal(t, "invalid input", resp.Message)
				assert.Equal(t, "validation", resp.Type)
			},
		},
		{
			name:           "not found error",
			err:            pkgerrors.NotFoundError("user", "123"),
			env:            "development",
			expectedStatus: http.StatusNotFound,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "not found")
				assert.Contains(t, resp.Message, "not found")
				assert.Equal(t, "not_found", resp.Type)
			},
		},
		{
			name:           "internal error",
			err:            pkgerrors.InternalError("database error", errors.New("connection failed")),
			env:            "development",
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "database error")
				assert.Equal(t, "An internal error occurred, please try again later", resp.Message)
				assert.Equal(t, "internal", resp.Type)
			},
		},
		{
			name:           "authentication error",
			err:            pkgerrors.PermissionError("authenticate", "resource"),
			env:            "development",
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "permission denied")
				assert.Equal(t, "You don't have permission to perform this action", resp.Message)
				assert.Equal(t, "permission", resp.Type)
			},
		},
		{
			name:           "authorization error",
			err:            pkgerrors.PermissionError("access", "admin resource"),
			env:            "development",
			expectedStatus: http.StatusForbidden,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "permission denied")
				assert.Equal(t, "You don't have permission to perform this action", resp.Message)
				assert.Equal(t, "permission", resp.Type)
			},
		},
		{
			name:           "conflict error",
			err:            pkgerrors.ConflictError("user", "username already exists"),
			env:            "development",
			expectedStatus: http.StatusConflict,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "conflict")
				assert.Equal(t, "The requested operation conflicts with the current state", resp.Message)
				assert.Equal(t, "conflict", resp.Type)
			},
		},
		{
			name:           "rate limit error",
			err:            pkgerrors.RateLimitError(100, "per minute"),
			env:            "development",
			expectedStatus: http.StatusTooManyRequests,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "rate limit exceeded")
				assert.Equal(t, "Too many requests, please try again later", resp.Message)
				assert.Equal(t, "rate_limit", resp.Type)
			},
		},
		{
			name:           "error with context",
			err:            pkgerrors.ValidationError("field error").WithContext("field", "email").WithContext("value", "invalid"),
			env:            "development",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "field error")
				assert.NotNil(t, resp.Context)
				assert.Equal(t, "email", resp.Context["field"])
				assert.Equal(t, "invalid", resp.Context["value"])
			},
		},
		{
			name:           "production environment - no type/context",
			err:            pkgerrors.ValidationError("field error").WithContext("field", "email"),
			env:            "production",
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "field error")
				assert.Empty(t, resp.Type)
				assert.Nil(t, resp.Context)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment
			if tt.env != "" {
				os.Setenv("ENV", tt.env)
			}

			// Create request and response recorder
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			// Handle error
			handleError(w, req, tt.err, logger)

			// Skip further checks if error was nil
			if tt.err == nil {
				return
			}

			// Assert status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Parse response
			var resp ErrorResponse
			err := json.NewDecoder(w.Body).Decode(&resp)
			require.NoError(t, err)

			// Check response
			if tt.checkResponse != nil {
				tt.checkResponse(t, resp)
			}

			// Check content type
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		})
	}
}

func TestRecoverPanic(t *testing.T) {
	logger := utils.NewLogger("", false)

	// Save original ENV
	originalEnv := os.Getenv("ENV")
	defer os.Setenv("ENV", originalEnv)

	tests := []struct {
		name           string
		handler        http.HandlerFunc
		env            string
		expectedStatus int
		checkResponse  func(t *testing.T, resp ErrorResponse)
	}{
		{
			name: "no panic",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "panic with string",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("something went wrong")
			},
			env:            "development",
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "internal server error")
				assert.Equal(t, "An internal error occurred, please try again later", resp.Message)
			},
		},
		{
			name: "panic with error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic(errors.New("critical error"))
			},
			env:            "development",
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "internal server error")
				assert.Equal(t, "An internal error occurred, please try again later", resp.Message)
			},
		},
		{
			name: "panic in production",
			handler: func(w http.ResponseWriter, r *http.Request) {
				panic("production panic")
			},
			env:            "production",
			expectedStatus: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, resp ErrorResponse) {
				assert.Contains(t, resp.Error, "internal server error")
				assert.Equal(t, "An internal error occurred, please try again later", resp.Message)
				assert.Empty(t, resp.Type)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment
			if tt.env != "" {
				os.Setenv("ENV", tt.env)
			}

			// Apply middleware
			middleware := RecoverPanic(logger)
			wrappedHandler := middleware(tt.handler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()

			// Execute request
			wrappedHandler.ServeHTTP(w, req)

			// Assert status code
			assert.Equal(t, tt.expectedStatus, w.Code)

			// Parse response if it's an error
			if tt.expectedStatus != http.StatusOK {
				var resp ErrorResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				require.NoError(t, err)

				if tt.checkResponse != nil {
					tt.checkResponse(t, resp)
				}
			}
		})
	}
}

func TestResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Test initial state
	assert.Equal(t, http.StatusOK, rw.statusCode)
	assert.Nil(t, rw.err)

	// Test WriteHeader
	rw.WriteHeader(http.StatusCreated)
	assert.Equal(t, http.StatusCreated, rw.statusCode)
	assert.Equal(t, http.StatusCreated, w.Code)

	// Test Write
	n, err := rw.Write([]byte("test"))
	assert.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.Equal(t, "test", w.Body.String())
}

func TestSetError(t *testing.T) {
	tests := []struct {
		name        string
		writer      http.ResponseWriter
		err         error
		shouldBeSet bool
	}{
		{
			name: "set error on responseWriter",
			writer: &responseWriter{
				ResponseWriter: httptest.NewRecorder(),
			},
			err:         errors.New("test error"),
			shouldBeSet: true,
		},
		{
			name:        "set error on regular ResponseWriter",
			writer:      httptest.NewRecorder(),
			err:         errors.New("test error"),
			shouldBeSet: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			SetError(tt.writer, tt.err)

			if rw, ok := tt.writer.(*responseWriter); ok && tt.shouldBeSet {
				assert.Equal(t, tt.err, rw.err)
			}
		})
	}
}

func TestIsProduction(t *testing.T) {
	// Save original ENV
	originalEnv := os.Getenv("ENV")
	defer os.Setenv("ENV", originalEnv)

	tests := []struct {
		env      string
		expected bool
	}{
		{"", false},
		{"development", false},
		{"dev", false},
		{"staging", false},
		{"production", true},
		{"prod", true},
		{"PRODUCTION", false}, // Case sensitive
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			os.Setenv("ENV", tt.env)
			assert.Equal(t, tt.expected, isProduction())
		})
	}
}

func TestErrorHandlerIntegration(t *testing.T) {
	logger := utils.NewLogger("", false)

	// Create a handler that uses custom errors
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/validation":
			err := pkgerrors.ValidationError("invalid email format").WithContext("field", "email")
			handleError(w, r, err, logger)
		case "/notfound":
			err := pkgerrors.NotFoundError("user", "123")
			handleError(w, r, err, logger)
		case "/internal":
			err := pkgerrors.New(pkgerrors.ErrorTypeInternal, "database connection failed")
			handleError(w, r, err, logger)
		default:
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		}
	})

	// Apply error handler middleware
	middleware := ErrorHandler(logger)
	wrappedHandler := middleware(handler)

	tests := []struct {
		path           string
		expectedStatus int
		expectedType   string
	}{
		{"/", http.StatusOK, ""},
		{"/validation", http.StatusBadRequest, "validation"},
		{"/notfound", http.StatusNotFound, "not_found"},
		{"/internal", http.StatusInternalServerError, "internal"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			wrappedHandler.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedType != "" {
				var resp ErrorResponse
				err := json.NewDecoder(w.Body).Decode(&resp)
				require.NoError(t, err)

				// In development mode, type should be present
				os.Setenv("ENV", "development")
				if !isProduction() {
					assert.Equal(t, tt.expectedType, resp.Type)
				}
			}
		})
	}
}