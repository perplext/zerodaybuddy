package ratelimit

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"
)

// RetryConfig holds configuration for retry logic
type RetryConfig struct {
	MaxAttempts     int           // Maximum number of retry attempts
	InitialDelay    time.Duration // Initial delay between retries
	MaxDelay        time.Duration // Maximum delay between retries
	Multiplier      float64       // Multiplier for exponential backoff
	JitterFactor    float64       // Jitter factor (0.0 to 1.0)
	RetryableErrors func(error) bool // Function to determine if error is retryable
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Second,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		JitterFactor: 0.1,
		RetryableErrors: func(err error) bool {
			// Default: retry on any error
			return true
		},
	}
}

// RetryableFunc is a function that can be retried
type RetryableFunc func(ctx context.Context) error

// RetryWithBackoff executes a function with exponential backoff retry logic
func RetryWithBackoff(ctx context.Context, config RetryConfig, fn RetryableFunc) error {
	var lastErr error
	
	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		// Execute the function
		err := fn(ctx)
		if err == nil {
			return nil
		}
		
		lastErr = err
		
		// Check if error is retryable
		if !config.RetryableErrors(err) {
			return err
		}
		
		// Check if this is the last attempt
		if attempt == config.MaxAttempts-1 {
			break
		}
		
		// Calculate delay with exponential backoff
		delay := calculateDelay(attempt, config)
		
		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			return fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}
	
	return fmt.Errorf("max retries (%d) exceeded: %w", config.MaxAttempts, lastErr)
}

// calculateDelay calculates the delay for a given attempt with jitter
func calculateDelay(attempt int, config RetryConfig) time.Duration {
	// Calculate base delay with exponential backoff
	baseDelay := float64(config.InitialDelay) * math.Pow(config.Multiplier, float64(attempt))
	
	// Cap at maximum delay
	if baseDelay > float64(config.MaxDelay) {
		baseDelay = float64(config.MaxDelay)
	}
	
	// Add jitter
	jitter := baseDelay * config.JitterFactor * (rand.Float64()*2 - 1) // -jitter to +jitter
	finalDelay := baseDelay + jitter
	
	// Ensure delay is not negative
	if finalDelay < 0 {
		finalDelay = 0
	}
	
	return time.Duration(finalDelay)
}

// RetryResult holds the result of a retry operation
type RetryResult struct {
	Attempts     int
	Success      bool
	LastError    error
	TotalLatency time.Duration
}

// RetryWithBackoffAndMetrics executes a function with retry logic and returns metrics
func RetryWithBackoffAndMetrics(ctx context.Context, config RetryConfig, fn RetryableFunc) (RetryResult, error) {
	result := RetryResult{}
	startTime := time.Now()
	var lastErr error
	
	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		result.Attempts = attempt + 1
		
		// Execute the function
		err := fn(ctx)
		if err == nil {
			result.Success = true
			result.TotalLatency = time.Since(startTime)
			return result, nil
		}
		
		lastErr = err
		result.LastError = err
		
		// Check if error is retryable
		if !config.RetryableErrors(err) {
			result.TotalLatency = time.Since(startTime)
			return result, err
		}
		
		// Check if this is the last attempt
		if attempt == config.MaxAttempts-1 {
			break
		}
		
		// Calculate delay with exponential backoff
		delay := calculateDelay(attempt, config)
		
		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			result.TotalLatency = time.Since(startTime)
			return result, fmt.Errorf("retry cancelled: %w", ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}
	
	result.TotalLatency = time.Since(startTime)
	return result, fmt.Errorf("max retries (%d) exceeded: %w", config.MaxAttempts, lastErr)
}