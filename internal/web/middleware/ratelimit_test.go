package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func newTestRateLimiter(rps float64, burst int) *RateLimiter {
	logger := utils.NewLogger("test", false)
	return &RateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		config:   RateLimitConfig{RequestsPerSecond: rps, Burst: burst},
		logger:   logger,
	}
}

func TestRateLimiter_AllowUnderLimit(t *testing.T) {
	rl := newTestRateLimiter(100, 10)
	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Send a few requests — all should succeed
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "1.2.3.4:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "request %d should be allowed", i)
	}
}

func TestRateLimiter_BlockOverLimit(t *testing.T) {
	// Very restrictive: 1 RPS, burst of 1
	rl := newTestRateLimiter(1, 1)
	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ip := "5.6.7.8:9999"

	// First request should succeed (uses the burst token)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = ip
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code, "first request should succeed")

	// Immediately following requests should be rate limited
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = ip
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code, "second request should be rate limited")
}

func TestRateLimiter_PerIPIsolation(t *testing.T) {
	// Very restrictive rate limit
	rl := newTestRateLimiter(1, 1)
	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust rate limit for IP A
	reqA := httptest.NewRequest("GET", "/", nil)
	reqA.RemoteAddr = "10.0.0.1:1111"
	recA := httptest.NewRecorder()
	handler.ServeHTTP(recA, reqA)
	assert.Equal(t, http.StatusOK, recA.Code)

	// IP A is now rate limited
	reqA2 := httptest.NewRequest("GET", "/", nil)
	reqA2.RemoteAddr = "10.0.0.1:2222"
	recA2 := httptest.NewRecorder()
	handler.ServeHTTP(recA2, reqA2)
	assert.Equal(t, http.StatusTooManyRequests, recA2.Code, "IP A should be rate limited")

	// IP B should NOT be rate limited
	reqB := httptest.NewRequest("GET", "/", nil)
	reqB.RemoteAddr = "10.0.0.2:3333"
	recB := httptest.NewRecorder()
	handler.ServeHTTP(recB, reqB)
	assert.Equal(t, http.StatusOK, recB.Code, "IP B should NOT be affected by IP A's limit")
}

func TestRateLimiter_ConcurrentAccess(t *testing.T) {
	rl := newTestRateLimiter(1000, 100)
	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	var wg sync.WaitGroup
	numGoroutines := 50

	// Concurrent requests from different IPs
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "192.168.1.1:12345" // same IP
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			// Should not panic — that's the main assertion for concurrency
		}(i)
	}

	wg.Wait()
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expected   string
	}{
		{"ip with port", "192.168.1.1:12345", "192.168.1.1"},
		{"ipv6 with port", "[::1]:8080", "::1"},
		{"bare ip (no port)", "192.168.1.1", "192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			got := clientIP(req)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestRateLimiter_GetLimiterCreatesEntry(t *testing.T) {
	rl := newTestRateLimiter(10, 5)

	// No limiter exists initially
	rl.mu.Lock()
	assert.Empty(t, rl.limiters)
	rl.mu.Unlock()

	// getLimiter should create one
	limiter := rl.getLimiter("1.2.3.4")
	assert.NotNil(t, limiter)

	rl.mu.Lock()
	assert.Len(t, rl.limiters, 1)
	rl.mu.Unlock()

	// Calling again should return same limiter
	limiter2 := rl.getLimiter("1.2.3.4")
	assert.Equal(t, limiter, limiter2)
}

func TestRateLimiter_ResponseBody(t *testing.T) {
	rl := newTestRateLimiter(1, 1)
	handler := rl.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Exhaust rate limit
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.1.1.1:1"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Second request should be blocked with "Too many requests"
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "1.1.1.1:2"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
	assert.Contains(t, rec2.Body.String(), "Too many requests")
}
