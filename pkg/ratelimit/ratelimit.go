package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter manages rate limiting for different services
type RateLimiter struct {
	limiters map[string]*serviceRateLimiter
	mu       sync.RWMutex
	config   Config
}

// serviceRateLimiter holds the rate limiter and metadata for a specific service
type serviceRateLimiter struct {
	limiter      *rate.Limiter
	name         string
	rps          float64
	burst        int
	lastAccessed time.Time
}

// Config holds rate limiter configuration
type Config struct {
	// Default rate limit settings
	DefaultRPS   float64       // Requests per second
	DefaultBurst int           // Burst capacity
	CleanupInterval time.Duration // How often to clean up unused limiters
	
	// Service-specific configurations
	Services map[string]ServiceConfig
}

// ServiceConfig holds rate limit configuration for a specific service
type ServiceConfig struct {
	RPS   float64 // Requests per second
	Burst int     // Burst capacity
}

// DefaultConfig returns a default rate limiter configuration
func DefaultConfig() Config {
	return Config{
		DefaultRPS:      10.0,
		DefaultBurst:    20,
		CleanupInterval: 5 * time.Minute,
		Services: map[string]ServiceConfig{
			"hackerone": {
				RPS:   2.0,  // 2 requests per second
				Burst: 5,
			},
			"bugcrowd": {
				RPS:   2.0,  // 2 requests per second
				Burst: 5,
			},
			"wayback": {
				RPS:   1.0,  // 1 request per second
				Burst: 3,
			},
			"nuclei": {
				RPS:   100.0, // 100 requests per second for scanning
				Burst: 200,
			},
			"default": {
				RPS:   10.0, // 10 requests per second default
				Burst: 20,
			},
		},
	}
}

// New creates a new RateLimiter instance
func New(config Config) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*serviceRateLimiter),
		config:   config,
	}
	
	// Start cleanup goroutine
	go rl.cleanup()
	
	return rl
}

// Wait blocks until a request can be made for the given service
func (rl *RateLimiter) Wait(ctx context.Context, service string) error {
	limiter := rl.getLimiter(service)
	return limiter.limiter.Wait(ctx)
}

// WaitN blocks until n requests can be made for the given service
func (rl *RateLimiter) WaitN(ctx context.Context, service string, n int) error {
	limiter := rl.getLimiter(service)
	return limiter.limiter.WaitN(ctx, n)
}

// Allow reports whether a request can be made for the given service
func (rl *RateLimiter) Allow(service string) bool {
	limiter := rl.getLimiter(service)
	return limiter.limiter.Allow()
}

// AllowN reports whether n requests can be made for the given service
func (rl *RateLimiter) AllowN(service string, n int) bool {
	limiter := rl.getLimiter(service)
	return limiter.limiter.AllowN(time.Now(), n)
}

// Reserve returns a reservation that can be used to wait or cancel
func (rl *RateLimiter) Reserve(service string) *rate.Reservation {
	limiter := rl.getLimiter(service)
	return limiter.limiter.Reserve()
}

// ReserveN returns a reservation for n requests
func (rl *RateLimiter) ReserveN(service string, n int) *rate.Reservation {
	limiter := rl.getLimiter(service)
	return limiter.limiter.ReserveN(time.Now(), n)
}

// getLimiter returns the rate limiter for a service, creating it if necessary
func (rl *RateLimiter) getLimiter(service string) *serviceRateLimiter {
	rl.mu.RLock()
	if limiter, exists := rl.limiters[service]; exists {
		rl.mu.RUnlock()
		// Update lastAccessed under write lock to avoid data race
		rl.mu.Lock()
		limiter.lastAccessed = time.Now()
		rl.mu.Unlock()
		return limiter
	}
	rl.mu.RUnlock()

	// Create new limiter
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if limiter, exists := rl.limiters[service]; exists {
		limiter.lastAccessed = time.Now()
		return limiter
	}
	
	// Get service config or use default
	config, exists := rl.config.Services[service]
	if !exists {
		config = ServiceConfig{
			RPS:   rl.config.DefaultRPS,
			Burst: rl.config.DefaultBurst,
		}
	}
	
	limiter := &serviceRateLimiter{
		limiter:      rate.NewLimiter(rate.Limit(config.RPS), config.Burst),
		name:         service,
		rps:          config.RPS,
		burst:        config.Burst,
		lastAccessed: time.Now(),
	}
	
	rl.limiters[service] = limiter
	return limiter
}

// cleanup periodically removes unused rate limiters
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for service, limiter := range rl.limiters {
			if now.Sub(limiter.lastAccessed) > rl.config.CleanupInterval*2 {
				delete(rl.limiters, service)
			}
		}
		rl.mu.Unlock()
	}
}

// GetStats returns statistics about current rate limiters
func (rl *RateLimiter) GetStats() map[string]Stats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	
	stats := make(map[string]Stats)
	for service, limiter := range rl.limiters {
		stats[service] = Stats{
			Service:      service,
			RPS:          limiter.rps,
			Burst:        limiter.burst,
			LastAccessed: limiter.lastAccessed,
		}
	}
	
	return stats
}

// Stats holds statistics for a rate limiter
type Stats struct {
	Service      string
	RPS          float64
	Burst        int
	LastAccessed time.Time
}

// UpdateServiceConfig updates the configuration for a specific service
func (rl *RateLimiter) UpdateServiceConfig(service string, config ServiceConfig) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	rl.config.Services[service] = config
	
	// Update existing limiter if present
	if limiter, exists := rl.limiters[service]; exists {
		limiter.limiter.SetLimit(rate.Limit(config.RPS))
		limiter.limiter.SetBurst(config.Burst)
		limiter.rps = config.RPS
		limiter.burst = config.Burst
	}
}

// String returns a string representation of the rate limiter stats
func (s Stats) String() string {
	return fmt.Sprintf("Service: %s, RPS: %.2f, Burst: %d, Last: %s",
		s.Service, s.RPS, s.Burst, s.LastAccessed.Format(time.RFC3339))
}