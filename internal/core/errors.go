package core

import (
	"fmt"
	"os"

	pkgerrors "github.com/perplext/zerodaybuddy/pkg/errors"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// HandleError handles errors in the CLI application
func HandleError(err error, logger *utils.Logger) {
	if err == nil {
		return
	}
	
	// Get error type and context
	errorType, isZeroDayBuddyError := pkgerrors.GetType(err)
	context := pkgerrors.GetContext(err)
	
	// Log the error with appropriate level
	if isZeroDayBuddyError {
		switch errorType {
		case pkgerrors.ErrorTypeValidation:
			logger.Debug("Validation error: %v", err)
		case pkgerrors.ErrorTypeNotFound:
			logger.Debug("Resource not found: %v", err)
		case pkgerrors.ErrorTypeConflict:
			logger.Warn("Resource conflict: %v", err)
		case pkgerrors.ErrorTypePermission:
			logger.Warn("Permission denied: %v", err)
		case pkgerrors.ErrorTypeRateLimit:
			logger.Warn("Rate limit exceeded: %v", err)
		case pkgerrors.ErrorTypeTimeout:
			logger.Error("Operation timeout: %v", err)
		case pkgerrors.ErrorTypeExternal:
			logger.Error("External service error: %v", err)
		case pkgerrors.ErrorTypeInternal:
			logger.Error("Internal error: %v", err)
		default:
			logger.Error("Unknown error type %s: %v", errorType, err)
		}
	} else {
		// For non-ZeroDayBuddy errors, log as internal error
		logger.Error("Unexpected error: %v", err)
	}
	
	// Print user-friendly message to stderr
	userMessage := pkgerrors.UserMessage(err)
	fmt.Fprintf(os.Stderr, "Error: %s\n", userMessage)
	
	// In debug mode, print additional details
	if isZeroDayBuddyError && len(context) > 0 {
		fmt.Fprintf(os.Stderr, "\nDebug Information:\n")
		fmt.Fprintf(os.Stderr, "  Type: %s\n", errorType)
		if len(context) > 0 {
			fmt.Fprintf(os.Stderr, "  Context:\n")
			for k, v := range context {
				fmt.Fprintf(os.Stderr, "    %s: %v\n", k, v)
			}
		}
	}
}

// ExitOnError handles an error and exits with appropriate code
func ExitOnError(err error, logger *utils.Logger) {
	if err == nil {
		return
	}
	
	HandleError(err, logger)
	
	// Determine exit code based on error type
	exitCode := 1 // Default exit code
	
	if errorType, ok := pkgerrors.GetType(err); ok {
		switch errorType {
		case pkgerrors.ErrorTypeValidation:
			exitCode = 2
		case pkgerrors.ErrorTypeNotFound:
			exitCode = 3
		case pkgerrors.ErrorTypeConflict:
			exitCode = 4
		case pkgerrors.ErrorTypePermission:
			exitCode = 5
		case pkgerrors.ErrorTypeRateLimit:
			exitCode = 6
		case pkgerrors.ErrorTypeTimeout:
			exitCode = 7
		case pkgerrors.ErrorTypeExternal:
			exitCode = 8
		case pkgerrors.ErrorTypeInternal:
			exitCode = 9
		}
	}
	
	os.Exit(exitCode)
}

// WrapCommandError wraps errors from command execution with context
func WrapCommandError(err error, command string, args map[string]interface{}) error {
	if err == nil {
		return nil
	}
	
	// If it's already a ZeroDayBuddy error, add command context
	if zerodaybuddyErr, ok := err.(*pkgerrors.ZeroDayBuddyError); ok {
		zerodaybuddyErr.WithContext("command", command)
		for k, v := range args {
			zerodaybuddyErr.WithContext(k, v)
		}
		return zerodaybuddyErr
	}
	
	// Otherwise, wrap it as an internal error
	wrapped := pkgerrors.InternalError(fmt.Sprintf("command '%s' failed", command), err)
	wrapped.WithContext("command", command)
	for k, v := range args {
		wrapped.WithContext(k, v)
	}
	
	return wrapped
}