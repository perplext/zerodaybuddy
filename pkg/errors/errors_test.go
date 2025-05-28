package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	err := New(ErrorTypeValidation, "invalid input")
	
	assert.NotNil(t, err)
	assert.Equal(t, ErrorTypeValidation, err.Type)
	assert.Equal(t, "invalid input", err.Message)
	assert.Nil(t, err.Err)
	assert.NotEmpty(t, err.StackTrace)
}

func TestWrap(t *testing.T) {
	originalErr := errors.New("original error")
	wrapped := Wrap(originalErr, ErrorTypeInternal, "something went wrong")
	
	assert.NotNil(t, wrapped)
	assert.Equal(t, ErrorTypeInternal, wrapped.Type)
	assert.Equal(t, "something went wrong", wrapped.Message)
	assert.Equal(t, originalErr, wrapped.Err)
	assert.NotEmpty(t, wrapped.StackTrace)
	
	// Test wrapping nil
	assert.Nil(t, Wrap(nil, ErrorTypeInternal, "message"))
}

func TestWrapZeroDayBuddyError(t *testing.T) {
	// Create original ZeroDayBuddyError with context
	original := New(ErrorTypeValidation, "validation failed").
		WithContext("field", "email").
		WithContext("value", "invalid")
	
	// Wrap it
	wrapped := Wrap(original, ErrorTypeInternal, "request failed")
	
	assert.NotNil(t, wrapped)
	assert.Equal(t, ErrorTypeInternal, wrapped.Type)
	assert.Equal(t, "request failed", wrapped.Message)
	assert.Equal(t, original, wrapped.Err)
	// Context should be preserved
	assert.Equal(t, original.Context, wrapped.Context)
}

func TestWithContext(t *testing.T) {
	err := New(ErrorTypeValidation, "invalid input").
		WithContext("field", "email").
		WithContext("value", "not-an-email")
	
	assert.NotNil(t, err.Context)
	assert.Equal(t, "email", err.Context["field"])
	assert.Equal(t, "not-an-email", err.Context["value"])
}

func TestError(t *testing.T) {
	// Test without wrapped error
	err1 := New(ErrorTypeValidation, "invalid input")
	assert.Equal(t, "validation: invalid input", err1.Error())
	
	// Test with wrapped error
	originalErr := errors.New("original error")
	err2 := Wrap(originalErr, ErrorTypeInternal, "something went wrong")
	assert.Equal(t, "internal: something went wrong: original error", err2.Error())
}

func TestUnwrap(t *testing.T) {
	originalErr := errors.New("original error")
	wrapped := Wrap(originalErr, ErrorTypeInternal, "something went wrong")
	
	unwrapped := wrapped.Unwrap()
	assert.Equal(t, originalErr, unwrapped)
}

func TestCommonConstructors(t *testing.T) {
	tests := []struct {
		name     string
		err      *ZeroDayBuddyError
		wantType ErrorType
		wantMsg  string
	}{
		{
			name:     "ValidationError",
			err:      ValidationError("field %s is required", "email"),
			wantType: ErrorTypeValidation,
			wantMsg:  "field email is required",
		},
		{
			name:     "NotFoundError",
			err:      NotFoundError("user", "123"),
			wantType: ErrorTypeNotFound,
			wantMsg:  "user with id '123' not found",
		},
		{
			name:     "ConflictError",
			err:      ConflictError("user", "email already exists"),
			wantType: ErrorTypeConflict,
			wantMsg:  "email already exists",
		},
		{
			name:     "PermissionError",
			err:      PermissionError("delete", "project"),
			wantType: ErrorTypePermission,
			wantMsg:  "permission denied for delete on project",
		},
		{
			name:     "RateLimitError",
			err:      RateLimitError(100, "1h"),
			wantType: ErrorTypeRateLimit,
			wantMsg:  "rate limit exceeded: 100 requests per 1h",
		},
		{
			name:     "TimeoutError",
			err:      TimeoutError("database query", "30s"),
			wantType: ErrorTypeTimeout,
			wantMsg:  "operation 'database query' timed out after 30s",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantType, tt.err.Type)
			assert.Equal(t, tt.wantMsg, tt.err.Message)
		})
	}
}

func TestIs(t *testing.T) {
	err := New(ErrorTypeValidation, "invalid input")
	
	assert.True(t, Is(err, ErrorTypeValidation))
	assert.False(t, Is(err, ErrorTypeNotFound))
	assert.False(t, Is(errors.New("regular error"), ErrorTypeValidation))
}

func TestGetType(t *testing.T) {
	// Test with ZeroDayBuddyError
	err1 := New(ErrorTypeValidation, "invalid input")
	errType, ok := GetType(err1)
	assert.True(t, ok)
	assert.Equal(t, ErrorTypeValidation, errType)
	
	// Test with regular error
	err2 := errors.New("regular error")
	errType, ok = GetType(err2)
	assert.False(t, ok)
	assert.Equal(t, ErrorType(""), errType)
}

func TestGetContext(t *testing.T) {
	// Test with context
	err1 := New(ErrorTypeValidation, "invalid input").
		WithContext("field", "email")
	ctx := GetContext(err1)
	assert.NotNil(t, ctx)
	assert.Equal(t, "email", ctx["field"])
	
	// Test without context
	err2 := New(ErrorTypeValidation, "invalid input")
	ctx = GetContext(err2)
	assert.Nil(t, ctx)
	
	// Test with regular error
	err3 := errors.New("regular error")
	ctx = GetContext(err3)
	assert.Nil(t, ctx)
}

func TestHTTPStatusCode(t *testing.T) {
	tests := []struct {
		err        error
		wantStatus int
	}{
		{New(ErrorTypeValidation, ""), 400},
		{New(ErrorTypeNotFound, ""), 404},
		{New(ErrorTypeConflict, ""), 409},
		{New(ErrorTypePermission, ""), 403},
		{New(ErrorTypeRateLimit, ""), 429},
		{New(ErrorTypeTimeout, ""), 504},
		{New(ErrorTypeExternal, ""), 502},
		{New(ErrorTypeInternal, ""), 500},
		{errors.New("regular error"), 500},
	}
	
	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			assert.Equal(t, tt.wantStatus, HTTPStatusCode(tt.err))
		})
	}
}

func TestUserMessage(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		wantMessage string
	}{
		{
			name:        "nil error",
			err:         nil,
			wantMessage: "",
		},
		{
			name:        "validation error",
			err:         ValidationError("email is invalid"),
			wantMessage: "email is invalid",
		},
		{
			name:        "not found error",
			err:         NotFoundError("user", "123"),
			wantMessage: "user with id '123' not found",
		},
		{
			name:        "conflict error",
			err:         ConflictError("user", "email already exists"),
			wantMessage: "The requested operation conflicts with the current state",
		},
		{
			name:        "permission error",
			err:         PermissionError("delete", "project"),
			wantMessage: "You don't have permission to perform this action",
		},
		{
			name:        "rate limit error",
			err:         RateLimitError(100, "1h"),
			wantMessage: "Too many requests, please try again later",
		},
		{
			name:        "timeout error",
			err:         TimeoutError("query", "30s"),
			wantMessage: "The operation timed out, please try again",
		},
		{
			name:        "external error",
			err:         ExternalError("github", errors.New("connection failed")),
			wantMessage: "An external service is currently unavailable",
		},
		{
			name:        "internal error",
			err:         InternalError("database error", errors.New("connection lost")),
			wantMessage: "An internal error occurred, please try again later",
		},
		{
			name:        "regular error",
			err:         errors.New("some error"),
			wantMessage: "An unexpected error occurred",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantMessage, UserMessage(tt.err))
		})
	}
}