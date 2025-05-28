package ratelimit

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRateLimiter_Basic(t *testing.T) {
	config := Config{
		DefaultRPS:      10.0,
		DefaultBurst:    5,
		CleanupInterval: 1 * time.Minute,
		Services:        make(map[string]ServiceConfig),
	}
	
	rl := New(config)
	
	// Test Allow
	if !rl.Allow("test-service") {
		t.Error("Expected Allow to return true for first request")
	}
	
	// Test multiple requests within burst
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow("test-service") {
			allowed++
		}
	}
	
	// Should allow up to burst limit
	if allowed > config.DefaultBurst {
		t.Errorf("Expected at most %d requests to be allowed, got %d", config.DefaultBurst, allowed)
	}
}

func TestRateLimiter_Wait(t *testing.T) {
	config := Config{
		DefaultRPS:      100.0, // High rate for testing
		DefaultBurst:    2,
		CleanupInterval: 1 * time.Minute,
		Services:        make(map[string]ServiceConfig),
	}
	
	rl := New(config)
	ctx := context.Background()
	
	// First requests should be immediate
	start := time.Now()
	for i := 0; i < config.DefaultBurst; i++ {
		if err := rl.Wait(ctx, "test-service"); err != nil {
			t.Fatalf("Wait failed: %v", err)
		}
	}
	
	// Should complete quickly (within burst)
	if time.Since(start) > 100*time.Millisecond {
		t.Error("Burst requests took too long")
	}
	
	// Next request should wait
	start = time.Now()
	if err := rl.Wait(ctx, "test-service"); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
	
	// Should have waited approximately 1/RPS seconds
	expectedWait := time.Second / 100 // 10ms for 100 RPS
	actualWait := time.Since(start)
	if actualWait < expectedWait/2 || actualWait > expectedWait*3 {
		t.Errorf("Expected wait of ~%v, got %v", expectedWait, actualWait)
	}
}

func TestRateLimiter_ServiceSpecific(t *testing.T) {
	config := Config{
		DefaultRPS:      10.0,
		DefaultBurst:    5,
		CleanupInterval: 1 * time.Minute,
		Services: map[string]ServiceConfig{
			"slow-service": {
				RPS:   1.0,
				Burst: 1,
			},
			"fast-service": {
				RPS:   100.0,
				Burst: 10,
			},
		},
	}
	
	rl := New(config)
	
	// Test slow service
	slowAllowed := 0
	for i := 0; i < 5; i++ {
		if rl.Allow("slow-service") {
			slowAllowed++
		}
	}
	if slowAllowed != 1 {
		t.Errorf("Expected 1 request for slow service, got %d", slowAllowed)
	}
	
	// Test fast service
	fastAllowed := 0
	for i := 0; i < 15; i++ {
		if rl.Allow("fast-service") {
			fastAllowed++
		}
	}
	if fastAllowed != 10 {
		t.Errorf("Expected 10 requests for fast service, got %d", fastAllowed)
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	config := Config{
		DefaultRPS:      50.0,
		DefaultBurst:    10,
		CleanupInterval: 1 * time.Minute,
		Services:        make(map[string]ServiceConfig),
	}
	
	rl := New(config)
	ctx := context.Background()
	
	// Run concurrent requests
	var wg sync.WaitGroup
	errors := make([]error, 20)
	
	start := time.Now()
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errors[idx] = rl.Wait(ctx, "concurrent-service")
		}(i)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
		}
	}
	
	// With 50 RPS and 10 burst, 20 requests should take about 200ms
	// (10 immediate, 10 more at 50/sec = 200ms)
	expectedDuration := 200 * time.Millisecond
	if duration < expectedDuration/2 || duration > expectedDuration*3 {
		t.Errorf("Expected duration ~%v, got %v", expectedDuration, duration)
	}
}

func TestRateLimiter_UpdateConfig(t *testing.T) {
	config := Config{
		DefaultRPS:      10.0,
		DefaultBurst:    5,
		CleanupInterval: 1 * time.Minute,
		Services:        make(map[string]ServiceConfig),
	}
	
	rl := New(config)
	
	// Use default config first
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow("update-service") {
			allowed++
		}
	}
	if allowed != 5 {
		t.Errorf("Expected 5 requests with default config, got %d", allowed)
	}
	
	// Update config
	rl.UpdateServiceConfig("update-service", ServiceConfig{
		RPS:   1.0,
		Burst: 2,
	})
	
	// Wait for tokens to replenish
	time.Sleep(3 * time.Second)
	
	// Test with new config
	allowed = 0
	for i := 0; i < 5; i++ {
		if rl.Allow("update-service") {
			allowed++
		}
	}
	if allowed != 2 {
		t.Errorf("Expected 2 requests with updated config, got %d", allowed)
	}
}

func TestRateLimiter_GetStats(t *testing.T) {
	config := Config{
		DefaultRPS:      10.0,
		DefaultBurst:    5,
		CleanupInterval: 1 * time.Minute,
		Services: map[string]ServiceConfig{
			"service1": {RPS: 5.0, Burst: 3},
		},
	}
	
	rl := New(config)
	
	// Use some services
	rl.Allow("service1")
	rl.Allow("service2")
	
	stats := rl.GetStats()
	
	if len(stats) != 2 {
		t.Errorf("Expected 2 services in stats, got %d", len(stats))
	}
	
	// Check service1 stats
	if s1, ok := stats["service1"]; ok {
		if s1.RPS != 5.0 || s1.Burst != 3 {
			t.Errorf("Service1 stats incorrect: RPS=%f, Burst=%d", s1.RPS, s1.Burst)
		}
	} else {
		t.Error("Service1 not found in stats")
	}
	
	// Check service2 uses defaults
	if s2, ok := stats["service2"]; ok {
		if s2.RPS != 10.0 || s2.Burst != 5 {
			t.Errorf("Service2 should use defaults: RPS=%f, Burst=%d", s2.RPS, s2.Burst)
		}
	} else {
		t.Error("Service2 not found in stats")
	}
}

func TestRateLimiter_ContextCancellation(t *testing.T) {
	config := Config{
		DefaultRPS:      1.0, // Very slow rate
		DefaultBurst:    1,
		CleanupInterval: 1 * time.Minute,
		Services:        make(map[string]ServiceConfig),
	}
	
	rl := New(config)
	
	// Use up the burst
	rl.Allow("cancel-service")
	
	// Create cancellable context
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	
	// This should timeout
	err := rl.Wait(ctx, "cancel-service")
	if err == nil {
		t.Error("Expected context cancellation error")
	}
	if !strings.Contains(err.Error(), "context deadline") {
		t.Errorf("Expected context deadline error, got: %v", err)
	}
}