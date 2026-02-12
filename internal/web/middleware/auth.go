package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// contextKey is a private type for context keys to prevent collisions.
type contextKey string

const userContextKey contextKey = "user"

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
			ctx := context.WithValue(r.Context(), userContextKey, user)
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
			ctx := context.WithValue(r.Context(), userContextKey, user)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// ContextWithUser returns a new context carrying the given user.
// Use this in tests to set up context the same way the middleware does.
func ContextWithUser(ctx context.Context, user *auth.User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// GetUserFromContext extracts user from request context
func GetUserFromContext(ctx context.Context) *auth.User {
	if user, ok := ctx.Value(userContextKey).(*auth.User); ok {
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