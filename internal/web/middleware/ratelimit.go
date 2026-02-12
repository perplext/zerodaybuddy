package middleware

import (
	"net"
	"net/http"
	"sync"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"golang.org/x/time/rate"
)

// RateLimitConfig defines per-path rate limits.
type RateLimitConfig struct {
	RequestsPerSecond float64
	Burst             int
}

// RateLimiter provides per-IP token-bucket rate limiting.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	config   RateLimitConfig
	logger   *utils.Logger
}

// NewRateLimiter creates a rate limiter with the given config.
func NewRateLimiter(cfg RateLimitConfig, logger *utils.Logger) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   cfg,
		logger:   logger,
	}
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(rl.config.RequestsPerSecond), rl.config.Burst)
		rl.limiters[ip] = limiter
	}
	return limiter
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
