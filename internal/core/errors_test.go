package core

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func captureStderr(f func()) string {
	old := os.Stderr
	defer func() { os.Stderr = old }()

	r, w, _ := os.Pipe()
	os.Stderr = w

	f()
	w.Close()

	var buf bytes.Buffer
	buf.ReadFrom(r)
	return buf.String()
}

func TestHandleError(t *testing.T) {
	logger := utils.NewLogger("", false)
	
	tests := []struct {
		name           string
		err            error
		expectedOutput string
	}{
		{
			name:           "nil error",
			err:            nil,
			expectedOutput: "",
		},
		{
			name:           "validation error",
			err:            pkgerrors.ValidationError("invalid input"),
			expectedOutput: "Error: invalid input",
		},
		{
			name:           "not found error",
			err:            pkgerrors.NotFoundError("project", "test-project"),
			expectedOutput: "Error: project with id 'test-project' not found",
		},
		{
			name:           "conflict error",
			err:            pkgerrors.ConflictError("project", "test-project"),
			expectedOutput: "Error: The requested operation conflicts with the current state",
		},
		{
			name:           "permission error",
			err:            pkgerrors.PermissionError("read", "project"),
			expectedOutput: "Error: You don't have permission to perform this action",
		},
		{
			name:           "rate limit error",
			err:            pkgerrors.RateLimitError(60, "minute"),
			expectedOutput: "Error: Too many requests, please try again later",
		},
		{
			name:           "timeout error",
			err:            pkgerrors.TimeoutError("scan", "30s"),
			expectedOutput: "Error: The operation timed out, please try again",
		},
		{
			name:           "external error",
			err:            pkgerrors.ExternalError("github", errors.New("API error")),
			expectedOutput: "Error: An external service is currently unavailable",
		},
		{
			name:           "internal error",
			err:            pkgerrors.New(pkgerrors.ErrorTypeInternal, "database connection failed"),
			expectedOutput: "Error: An internal error occurred, please try again later",
		},
		{
			name:           "generic error",
			err:            errors.New("something went wrong"),
			expectedOutput: "Error: An unexpected error occurred",
		},
		{
			name: "error with context",
			err: pkgerrors.ValidationError("invalid parameter").
				WithContext("param", "concurrency").
				WithContext("value", -1),
			expectedOutput: "Error: invalid parameter",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := captureStderr(func() {
				HandleError(tt.err, logger)
			})
			
			if tt.expectedOutput == "" {
				assert.Empty(t, output)
			} else {
				assert.Contains(t, output, tt.expectedOutput)
			}
		})
	}
}

func TestExitOnError(t *testing.T) {
	if os.Getenv("BE_EXIT_TEST") == "1" {
		logger := utils.NewLogger("", false)
		
		var err error
		switch os.Getenv("EXIT_ERROR_TYPE") {
		case "validation":
			err = pkgerrors.ValidationError("test")
		case "notfound":
			err = pkgerrors.NotFoundError("resource", "test")
		case "conflict":
			err = pkgerrors.ConflictError("resource", "test")
		case "permission":
			err = pkgerrors.PermissionError("test", "resource")
		case "ratelimit":
			err = pkgerrors.RateLimitError(60, "minute")
		case "timeout":
			err = pkgerrors.TimeoutError("test", "30s")
		case "external":
			err = pkgerrors.ExternalError("test", errors.New("test"))
		case "internal":
			err = pkgerrors.New(pkgerrors.ErrorTypeInternal, "test")
		default:
			err = errors.New("test error")
		}
		
		ExitOnError(err, logger)
		return
	}
	
	tests := []struct {
		name         string
		errorType    string
		expectedCode int
	}{
		{"validation error", "validation", 2},
		{"not found error", "notfound", 3},
		{"conflict error", "conflict", 4},
		{"permission error", "permission", 5},
		{"rate limit error", "ratelimit", 6},
		{"timeout error", "timeout", 7},
		{"external error", "external", 8},
		{"internal error", "internal", 9},
		{"generic error", "generic", 1},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := os.Args[0]
			args := []string{"-test.run=TestExitOnError"}
			cmd = fmt.Sprintf("%s %s", cmd, strings.Join(args, " "))
			
			env := []string{
				"BE_EXIT_TEST=1",
				fmt.Sprintf("EXIT_ERROR_TYPE=%s", tt.errorType),
			}
			
			exitCode := os.Getenv("EXIT_CODE")
			if exitCode != "" {
				// Running in subprocess, skip
				return
			}
			
			// Execute in subprocess
			proc := exec.Command(os.Args[0], "-test.run=TestExitOnError")
			proc.Env = append(os.Environ(), env...)
			err := proc.Run()
			
			if e, ok := err.(*exec.ExitError); ok {
				assert.Equal(t, tt.expectedCode, e.ExitCode())
			} else {
				t.Fatalf("process ran with err %v, want exit code %d", err, tt.expectedCode)
			}
		})
	}
}

func TestExitOnErrorNil(t *testing.T) {
	logger := utils.NewLogger("", false)
	// Should not exit or panic on nil error
	ExitOnError(nil, logger)
	assert.True(t, true) // If we reach here, test passes
}

func TestWrapCommandError(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		command        string
		args           map[string]interface{}
		expectedType   pkgerrors.ErrorType
		expectedMsg    string
		expectedContext map[string]interface{}
	}{
		{
			name:         "nil error",
			err:          nil,
			command:      "test",
			args:         nil,
			expectedType: "",
			expectedMsg:  "",
		},
		{
			name:    "wrap ZeroDayBuddy error",
			err:     pkgerrors.ValidationError("invalid input"),
			command: "validate",
			args: map[string]interface{}{
				"input": "test",
			},
			expectedType: pkgerrors.ErrorTypeValidation,
			expectedMsg:  "invalid input",
			expectedContext: map[string]interface{}{
				"command": "validate",
				"input":   "test",
			},
		},
		{
			name:    "wrap generic error",
			err:     errors.New("something failed"),
			command: "process",
			args: map[string]interface{}{
				"file": "test.txt",
			},
			expectedType: pkgerrors.ErrorTypeInternal,
			expectedMsg:  "command 'process' failed: something failed",
			expectedContext: map[string]interface{}{
				"command": "process",
				"file":    "test.txt",
			},
		},
		{
			name:         "wrap error without args",
			err:          errors.New("failed"),
			command:      "run",
			args:         nil,
			expectedType: pkgerrors.ErrorTypeInternal,
			expectedMsg:  "command 'run' failed: failed",
			expectedContext: map[string]interface{}{
				"command": "run",
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapped := WrapCommandError(tt.err, tt.command, tt.args)
			
			if tt.err == nil {
				assert.Nil(t, wrapped)
				return
			}
			
			assert.NotNil(t, wrapped)
			
			// Check error type
			errType, ok := pkgerrors.GetType(wrapped)
			assert.True(t, ok)
			assert.Equal(t, tt.expectedType, errType)
			
			// Check error message
			assert.Contains(t, wrapped.Error(), tt.expectedMsg)
			
			// Check context
			context := pkgerrors.GetContext(wrapped)
			for k, v := range tt.expectedContext {
				assert.Equal(t, v, context[k])
			}
		})
	}
}