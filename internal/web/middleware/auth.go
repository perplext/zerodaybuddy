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

// SessionCookieName is the name of the cookie carrying the JWT for browser
// sessions. Same JWT as the Authorization: Bearer header — different transport.
// Browser handlers (T2-3) set this cookie at login and clear it at logout.
const SessionCookieName = "zdb_session"

// AuthService interface for authentication operations
type AuthService interface {
	ValidateToken(ctx context.Context, token string) (*auth.User, error)
}

// tokenFromRequest extracts a JWT from the request, looking first at the
// Authorization: Bearer header, then falling back to the SessionCookieName
// cookie. The Authorization header takes precedence when both are present
// (more explicit; matches typical API-client expectations).
//
// Returns the raw token string and ok=true on success. Returns ok=false when
// neither source carries a valid Bearer token.
func tokenFromRequest(r *http.Request) (string, bool) {
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" && parts[1] != "" {
			return parts[1], true
		}
		// Header was present but malformed — fall through to cookie. The
		// alternative (rejecting outright) would surprise mixed-transport
		// clients (e.g., a browser that has both a cookie and a stale
		// header from a JS extension).
	}
	if cookie, err := r.Cookie(SessionCookieName); err == nil && cookie.Value != "" {
		return cookie.Value, true
	}
	return "", false
}

// AuthMiddleware handles JWT token authentication. Accepts the JWT from
// either the Authorization: Bearer header (API clients) or the
// SessionCookieName cookie (browser flow). On any failure (no token,
// invalid token, expired token), returns 401 plain-text — same shape as
// before T2-3.
func AuthMiddleware(authService AuthService, logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := tokenFromRequest(r)
			if !ok {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}

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

// OptionalAuth validates a token if one is present (in either the
// Authorization header or the SessionCookieName cookie) but never fails the
// request. Used by browser routes that want to know who the user is when
// possible but render a generic page (or 303 to /login) when not authed.
func OptionalAuth(authService AuthService, logger *utils.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := tokenFromRequest(r)
			if !ok {
				// No token provided, continue without authentication
				next.ServeHTTP(w, r)
				return
			}

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