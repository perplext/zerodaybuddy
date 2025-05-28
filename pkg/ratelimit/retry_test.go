package ratelimit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRetryWithBackoff_Success(t *testing.T) {
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond
	
	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		if attempts < 2 {
			return errors.New("temporary error")
		}
		return nil
	}
	
	err := RetryWithBackoff(context.Background(), config, fn)
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", attempts)
	}
}

func TestRetryWithBackoff_MaxAttemptsExceeded(t *testing.T) {
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond
	
	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		return errors.New("persistent error")
	}
	
	err := RetryWithBackoff(context.Background(), config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	
	if !strings.Contains(err.Error(), "max retries (3) exceeded") {
		t.Errorf("Expected max retries error, got: %v", err)
	}
	
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestRetryWithBackoff_NonRetryableError(t *testing.T) {
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond
	config.RetryableErrors = func(err error) bool {
		return !strings.Contains(err.Error(), "fatal")
	}
	
	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		return errors.New("fatal error")
	}
	
	err := RetryWithBackoff(context.Background(), config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	
	if !strings.Contains(err.Error(), "fatal error") {
		t.Errorf("Expected fatal error, got: %v", err)
	}
	
	if attempts != 1 {
		t.Errorf("Expected 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestRetryWithBackoff_ContextCancellation(t *testing.T) {
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 100 * time.Millisecond
	
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	
	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		return errors.New("error")
	}
	
	err := RetryWithBackoff(ctx, config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	
	if !strings.Contains(err.Error(), "retry cancelled") {
		t.Errorf("Expected cancellation error, got: %v", err)
	}
	
	if attempts != 1 {
		t.Errorf("Expected 1 attempt before cancellation, got %d", attempts)
	}
}

func TestCalculateDelay(t *testing.T) {
	config := DefaultRetryConfig()
	config.InitialDelay = 100 * time.Millisecond
	config.MaxDelay = 1 * time.Second
	config.Multiplier = 2.0
	config.JitterFactor = 0.0 // No jitter for predictable tests
	
	tests := []struct {
		attempt      int
		expectedMin  time.Duration
		expectedMax  time.Duration
	}{
		{0, 100 * time.Millisecond, 100 * time.Millisecond},
		{1, 200 * time.Millisecond, 200 * time.Millisecond},
		{2, 400 * time.Millisecond, 400 * time.Millisecond},
		{3, 800 * time.Millisecond, 800 * time.Millisecond},
		{4, 1 * time.Second, 1 * time.Second}, // Capped at max
		{5, 1 * time.Second, 1 * time.Second}, // Still capped
	}
	
	for _, test := range tests {
		delay := calculateDelay(test.attempt, config)
		if delay < test.expectedMin || delay > test.expectedMax {
			t.Errorf("Attempt %d: expected delay between %v and %v, got %v",
				test.attempt, test.expectedMin, test.expectedMax, delay)
		}
	}
}

func TestCalculateDelay_WithJitter(t *testing.T) {
	config := DefaultRetryConfig()
	config.InitialDelay = 100 * time.Millisecond
	config.MaxDelay = 10 * time.Second
	config.Multiplier = 2.0
	config.JitterFactor = 0.2
	
	// Run multiple times to test jitter
	for i := 0; i < 10; i++ {
		delay := calculateDelay(1, config)
		baseDelay := 200 * time.Millisecond
		minDelay := time.Duration(float64(baseDelay) * 0.8)
		maxDelay := time.Duration(float64(baseDelay) * 1.2)
		
		if delay < minDelay || delay > maxDelay {
			t.Errorf("Iteration %d: delay %v outside jitter range [%v, %v]",
				i, delay, minDelay, maxDelay)
		}
	}
}

func TestRetryWithBackoffAndMetrics(t *testing.T) {
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond
	
	attempts := 0
	fn := func(ctx context.Context) error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary error")
		}
		return nil
	}
	
	result, err := RetryWithBackoffAndMetrics(context.Background(), config, fn)
	if err != nil {
		t.Errorf("Expected success, got error: %v", err)
	}
	
	if !result.Success {
		t.Error("Expected success flag to be true")
	}
	
	if result.Attempts != 3 {
		t.Errorf("Expected 3 attempts in result, got %d", result.Attempts)
	}
	
	// LastError holds the last error before success, which is expected
	if result.LastError == nil && attempts > 1 {
		t.Error("Expected last error to be set when there were failed attempts")
	}
	
	if result.TotalLatency < 20*time.Millisecond {
		t.Errorf("Expected total latency > 20ms (2 delays), got %v", result.TotalLatency)
	}
}

func TestDefaultRetryableErrors(t *testing.T) {
	fn := DefaultRetryableErrors()
	
	tests := []struct {
		err       error
		retryable bool
	}{
		{nil, false},
		{errors.New("connection refused"), true},
		{errors.New("connection reset by peer"), true},
		{errors.New("no such host"), true},
		{errors.New("request timeout"), true},
		{errors.New("temporary failure"), true},
		{errors.New("unexpected EOF"), true},
		{errors.New("rate limited by server (429)"), true},
		{errors.New("server error: 500"), true},
		{errors.New("server error: 503"), true},
		{errors.New("bad request"), false},
		{errors.New("unauthorized"), false},
		{errors.New("not found"), false},
	}
	
	for _, test := range tests {
		result := fn(test.err)
		if result != test.retryable {
			t.Errorf("Error '%v': expected retryable=%v, got %v", 
				test.err, test.retryable, result)
		}
	}
}