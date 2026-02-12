package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"golang.org/x/time/rate"
)

// RateLimitConfig defines per-path rate limits.
type RateLimitConfig struct {
	RequestsPerSecond float64
	Burst             int
}

// rateLimiterEntry holds a limiter and its last-access time for eviction.
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

// RateLimiter provides per-IP token-bucket rate limiting.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rateLimiterEntry
	config   RateLimitConfig
	logger   *utils.Logger
}

const rateLimiterCleanupInterval = 10 * time.Minute
const rateLimiterEntryTTL = 10 * time.Minute

// NewRateLimiter creates a rate limiter with the given config.
func NewRateLimiter(cfg RateLimitConfig, logger *utils.Logger) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*rateLimiterEntry),
		config:   cfg,
		logger:   logger,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, exists := rl.limiters[ip]
	if !exists {
		entry = &rateLimiterEntry{
			limiter: rate.NewLimiter(rate.Limit(rl.config.RequestsPerSecond), rl.config.Burst),
		}
		rl.limiters[ip] = entry
	}
	entry.lastAccess = time.Now()
	return entry.limiter
}

// cleanup periodically evicts stale per-IP limiters.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rateLimiterCleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, entry := range rl.limiters {
			if now.Sub(entry.lastAccess) > rateLimiterEntryTTL {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Middleware returns an http middleware that enforces rate limits per IP.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			limiter := rl.getLimiter(ip)

			if !limiter.Allow() {
				rl.logger.Warn("Rate limit exceeded for %s on %s %s", ip, r.Method, r.URL.Path)
				http.Error(w, "Too many requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
