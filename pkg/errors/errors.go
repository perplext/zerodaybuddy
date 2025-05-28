package errors

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

// Error types for different categories
type ErrorType string

const (
	// ErrorTypeValidation indicates input validation errors
	ErrorTypeValidation ErrorType = "validation"
	// ErrorTypeNotFound indicates resource not found errors
	ErrorTypeNotFound ErrorType = "not_found"
	// ErrorTypeConflict indicates resource conflict errors
	ErrorTypeConflict ErrorType = "conflict"
	// ErrorTypeInternal indicates internal server errors
	ErrorTypeInternal ErrorType = "internal"
	// ErrorTypeExternal indicates external service errors
	ErrorTypeExternal ErrorType = "external"
	// ErrorTypePermission indicates permission/authorization errors
	ErrorTypePermission ErrorType = "permission"
	// ErrorTypeRateLimit indicates rate limiting errors
	ErrorTypeRateLimit ErrorType = "rate_limit"
	// ErrorTypeTimeout indicates timeout errors
	ErrorTypeTimeout ErrorType = "timeout"
)

// ZeroDayBuddyError is the base error type for all ZeroDayBuddy errors
type ZeroDayBuddyError struct {
	Type       ErrorType
	Message    string
	Err        error
	Context    map[string]interface{}
	StackTrace string
}

// Error implements the error interface
func (e *ZeroDayBuddyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap allows errors.Is and errors.As to work
func (e *ZeroDayBuddyError) Unwrap() error {
	return e.Err
}

// WithContext adds context to the error
func (e *ZeroDayBuddyError) WithContext(key string, value interface{}) *ZeroDayBuddyError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// New creates a new ZeroDayBuddyError
func New(errorType ErrorType, message string) *ZeroDayBuddyError {
	return &ZeroDayBuddyError{
		Type:       errorType,
		Message:    message,
		StackTrace: getStackTrace(),
	}
}

// Wrap wraps an existing error with ZeroDayBuddyError
func Wrap(err error, errorType ErrorType, message string) *ZeroDayBuddyError {
	if err == nil {
		return nil
	}
	
	// If it's already a ZeroDayBuddyError, preserve the original context
	if zerodaybuddyErr, ok := err.(*ZeroDayBuddyError); ok {
		return &ZeroDayBuddyError{
			Type:       errorType,
			Message:    message,
			Err:        zerodaybuddyErr,
			Context:    zerodaybuddyErr.Context,
			StackTrace: zerodaybuddyErr.StackTrace,
		}
	}
	
	return &ZeroDayBuddyError{
		Type:       errorType,
		Message:    message,
		Err:        err,
		StackTrace: getStackTrace(),
	}
}

// Common error constructors

// ValidationError creates a validation error
func ValidationError(message string, args ...interface{}) *ZeroDayBuddyError {
	return New(ErrorTypeValidation, fmt.Sprintf(message, args...))
}

// NotFoundError creates a not found error
func NotFoundError(resource string, id string) *ZeroDayBuddyError {
	return New(ErrorTypeNotFound, fmt.Sprintf("%s with id '%s' not found", resource, id)).
		WithContext("resource", resource).
		WithContext("id", id)
}

// ConflictError creates a conflict error
func ConflictError(resource string, message string) *ZeroDayBuddyError {
	return New(ErrorTypeConflict, message).
		WithContext("resource", resource)
}

// InternalError creates an internal error
func InternalError(message string, err error) *ZeroDayBuddyError {
	return Wrap(err, ErrorTypeInternal, message)
}

// ExternalError creates an external service error
func ExternalError(service string, err error) *ZeroDayBuddyError {
	return Wrap(err, ErrorTypeExternal, fmt.Sprintf("external service error: %s", service)).
		WithContext("service", service)
}

// PermissionError creates a permission error
func PermissionError(action string, resource string) *ZeroDayBuddyError {
	return New(ErrorTypePermission, fmt.Sprintf("permission denied for %s on %s", action, resource)).
		WithContext("action", action).
		WithContext("resource", resource)
}

// RateLimitError creates a rate limit error
func RateLimitError(limit int, window string) *ZeroDayBuddyError {
	return New(ErrorTypeRateLimit, fmt.Sprintf("rate limit exceeded: %d requests per %s", limit, window)).
		WithContext("limit", limit).
		WithContext("window", window)
}

// TimeoutError creates a timeout error
func TimeoutError(operation string, duration string) *ZeroDayBuddyError {
	return New(ErrorTypeTimeout, fmt.Sprintf("operation '%s' timed out after %s", operation, duration)).
		WithContext("operation", operation).
		WithContext("duration", duration)
}

// Helper functions

// Is checks if an error is of a specific type
func Is(err error, errorType ErrorType) bool {
	var zerodaybuddyErr *ZeroDayBuddyError
	if errors.As(err, &zerodaybuddyErr) {
		return zerodaybuddyErr.Type == errorType
	}
	return false
}

// GetType returns the error type if it's a ZeroDayBuddyError
func GetType(err error) (ErrorType, bool) {
	var zerodaybuddyErr *ZeroDayBuddyError
	if errors.As(err, &zerodaybuddyErr) {
		return zerodaybuddyErr.Type, true
	}
	return "", false
}

// GetContext returns the context of a ZeroDayBuddyError
func GetContext(err error) map[string]interface{} {
	var zerodaybuddyErr *ZeroDayBuddyError
	if errors.As(err, &zerodaybuddyErr) {
		return zerodaybuddyErr.Context
	}
	return nil
}

// HTTPStatusCode returns appropriate HTTP status code for error type
func HTTPStatusCode(err error) int {
	errorType, ok := GetType(err)
	if !ok {
		return 500 // Internal Server Error for unknown errors
	}
	
	switch errorType {
	case ErrorTypeValidation:
		return 400 // Bad Request
	case ErrorTypeNotFound:
		return 404 // Not Found
	case ErrorTypeConflict:
		return 409 // Conflict
	case ErrorTypePermission:
		return 403 // Forbidden
	case ErrorTypeRateLimit:
		return 429 // Too Many Requests
	case ErrorTypeTimeout:
		return 504 // Gateway Timeout
	case ErrorTypeExternal:
		return 502 // Bad Gateway
	case ErrorTypeInternal:
		return 500 // Internal Server Error
	default:
		return 500
	}
}

// UserMessage returns a user-friendly error message
func UserMessage(err error) string {
	if err == nil {
		return ""
	}
	
	var zerodaybuddyErr *ZeroDayBuddyError
	if errors.As(err, &zerodaybuddyErr) {
		switch zerodaybuddyErr.Type {
		case ErrorTypeValidation:
			return zerodaybuddyErr.Message
		case ErrorTypeNotFound:
			return zerodaybuddyErr.Message
		case ErrorTypeConflict:
			return "The requested operation conflicts with the current state"
		case ErrorTypePermission:
			return "You don't have permission to perform this action"
		case ErrorTypeRateLimit:
			return "Too many requests, please try again later"
		case ErrorTypeTimeout:
			return "The operation timed out, please try again"
		case ErrorTypeExternal:
			return "An external service is currently unavailable"
		case ErrorTypeInternal:
			return "An internal error occurred, please try again later"
		default:
			return "An unexpected error occurred"
		}
	}
	
	return "An unexpected error occurred"
}

// getStackTrace captures the current stack trace
func getStackTrace() string {
	const depth = 32
	var pcs [depth]uintptr
	n := runtime.Callers(3, pcs[:])
	
	var builder strings.Builder
	frames := runtime.CallersFrames(pcs[:n])
	
	for {
		frame, more := frames.Next()
		// Skip runtime and errors package frames
		if !strings.Contains(frame.File, "runtime/") && !strings.Contains(frame.File, "pkg/errors") {
			builder.WriteString(fmt.Sprintf("%s:%d %s\n", frame.File, frame.Line, frame.Function))
		}
		if !more {
			break
		}
	}
	
	return builder.String()
}