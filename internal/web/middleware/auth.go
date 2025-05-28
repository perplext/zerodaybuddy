package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// AuthService interface for authentication operations
type AuthService interface {
	ValidateToken(ctx context.Context, token string) (*auth.User, error)
}

// AuthMiddleware handles JWT token authentication
func AuthMiddleware(authService AuthService, logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

			// Check Bearer token format
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
				return
			}

			token := parts[1]

			// Validate token
			user, err := authService.ValidateToken(r.Context(), token)
			if err != nil {
				logger.Debug("Token validation failed: %v", err)
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
				return
			}

			// Add user to context
			ctx := context.WithValue(r.Context(), "user", user)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole middleware that checks user role
func RequireRole(requiredRole auth.UserRole, logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			if !user.HasPermission(requiredRole) {
				logger.Warn("User %s attempted to access resource requiring %s role", user.Username, requiredRole)
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuth middleware that validates token if present but doesn't require it
func OptionalAuth(authService AuthService, logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				// No token provided, continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			// Check Bearer token format
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				// Invalid format, but don't fail since auth is optional
				next.ServeHTTP(w, r)
				return
			}

			token := parts[1]

			// Validate token
			user, err := authService.ValidateToken(r.Context(), token)
			if err != nil {
				logger.Debug("Optional token validation failed: %v", err)
				// Invalid token, but continue without authentication
				next.ServeHTTP(w, r)
				return
			}

			// Add user to context
			ctx := context.WithValue(r.Context(), "user", user)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// CSRF middleware for CSRF protection
func CSRF(logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF check for GET, HEAD, OPTIONS requests
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}

			// Get CSRF token from header
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				// Try to get from form data
				csrfToken = r.FormValue("csrf_token")
			}

			if csrfToken == "" {
				logger.Warn("CSRF token missing for %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
				http.Error(w, "CSRF token required", http.StatusForbidden)
				return
			}

			// For now, we'll implement a simple token validation
			// In production, you'd want to validate against a session-specific token
			if len(csrfToken) < 16 {
				logger.Warn("Invalid CSRF token for %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
				http.Error(w, "Invalid CSRF token", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware implements basic rate limiting
func RateLimitMiddleware(requestsPerMinute int, logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// For production, use a proper rate limiting library like golang.org/x/time/rate
			// This is a placeholder implementation
			
			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext extracts user from request context
func GetUserFromContext(ctx context.Context) *auth.User {
	if user, ok := ctx.Value("user").(*auth.User); ok {
		return user
	}
	return nil
}

// RequireAuth ensures user is authenticated
func RequireAuth(logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := GetUserFromContext(r.Context())
			if user == nil {
				http.Error(w, "Authentication required", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AdminOnly restricts access to admin users only
func AdminOnly(logger *utils.Logger) func(http.Handler) http.Handler {
	return RequireRole(auth.RoleAdmin, logger)
}

// UserOrAdmin allows access to regular users or admins
func UserOrAdmin(logger *utils.Logger) func(http.Handler) http.Handler {
	return RequireRole(auth.RoleUser, logger)
}