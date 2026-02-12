package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockAuthService is a mock implementation of AuthService
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) ValidateToken(ctx context.Context, token string) (*auth.User, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func TestAuthMiddleware(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		authHeader     string
		mockSetup      func(*MockAuthService)
		expectedStatus int
		expectedBody   string
		checkContext   func(*testing.T, *http.Request)
	}{
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Authorization header required",
		},
		{
			name:           "invalid authorization format - no bearer",
			authHeader:     "InvalidToken",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid authorization header format",
		},
		{
			name:           "invalid authorization format - wrong prefix",
			authHeader:     "Basic dGVzdDp0ZXN0",
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid authorization header format",
		},
		{
			name:       "invalid token",
			authHeader: "Bearer invalid-token",
			mockSetup: func(m *MockAuthService) {
				m.On("ValidateToken", mock.Anything, "invalid-token").Return(nil, errors.New("invalid token"))
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Invalid or expired token",
		},
		{
			name:       "valid token",
			authHeader: "Bearer valid-token",
			mockSetup: func(m *MockAuthService) {
				user := &auth.User{
					ID:       "user123",
					Username: "testuser",
					Email:    "test@example.com",
					Role:     auth.RoleUser,
				}
				m.On("ValidateToken", mock.Anything, "valid-token").Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
			checkContext: func(t *testing.T, r *http.Request) {
				user := GetUserFromContext(r.Context())
				assert.NotNil(t, user)
				assert.Equal(t, "user123", user.ID)
				assert.Equal(t, "testuser", user.Username)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := new(MockAuthService)
			if tt.mockSetup != nil {
				tt.mockSetup(mockAuth)
			}

			// Create test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.checkContext != nil {
					tt.checkContext(t, r)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			// Apply middleware
			middleware := AuthMiddleware(mockAuth, logger)
			wrappedHandler := middleware(handler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Execute request
			w := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestRequireRole(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		user           *auth.User
		requiredRole   auth.UserRole
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "no user in context",
			user:           nil,
			requiredRole:   auth.RoleUser,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Authentication required",
		},
		{
			name: "insufficient permissions - user requires admin",
			user: &auth.User{
				ID:   "user123",
				Role: auth.RoleUser,
			},
			requiredRole:   auth.RoleAdmin,
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Insufficient permissions",
		},
		{
			name: "sufficient permissions - admin as admin",
			user: &auth.User{
				ID:   "admin123",
				Role: auth.RoleAdmin,
			},
			requiredRole:   auth.RoleAdmin,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name: "sufficient permissions - admin as user",
			user: &auth.User{
				ID:   "admin123",
				Role: auth.RoleAdmin,
			},
			requiredRole:   auth.RoleUser,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
		{
			name: "sufficient permissions - user as user",
			user: &auth.User{
				ID:   "user123",
				Role: auth.RoleUser,
			},
			requiredRole:   auth.RoleUser,
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			// Apply middleware
			middleware := RequireRole(tt.requiredRole, logger)
			wrappedHandler := middleware(handler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.user != nil {
				ctx := context.WithValue(req.Context(), userContextKey, tt.user)
				req = req.WithContext(ctx)
			}

			// Execute request
			w := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)
		})
	}
}

func TestOptionalAuth(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		authHeader     string
		mockSetup      func(*MockAuthService)
		expectedStatus int
		checkContext   func(*testing.T, *http.Request)
	}{
		{
			name:           "no authorization header",
			authHeader:     "",
			expectedStatus: http.StatusOK,
			checkContext: func(t *testing.T, r *http.Request) {
				user := GetUserFromContext(r.Context())
				assert.Nil(t, user)
			},
		},
		{
			name:           "invalid format - continues without auth",
			authHeader:     "InvalidFormat",
			expectedStatus: http.StatusOK,
			checkContext: func(t *testing.T, r *http.Request) {
				user := GetUserFromContext(r.Context())
				assert.Nil(t, user)
			},
		},
		{
			name:       "invalid token - continues without auth",
			authHeader: "Bearer invalid-token",
			mockSetup: func(m *MockAuthService) {
				m.On("ValidateToken", mock.Anything, "invalid-token").Return(nil, errors.New("invalid token"))
			},
			expectedStatus: http.StatusOK,
			checkContext: func(t *testing.T, r *http.Request) {
				user := GetUserFromContext(r.Context())
				assert.Nil(t, user)
			},
		},
		{
			name:       "valid token - adds user to context",
			authHeader: "Bearer valid-token",
			mockSetup: func(m *MockAuthService) {
				user := &auth.User{
					ID:       "user123",
					Username: "testuser",
				}
				m.On("ValidateToken", mock.Anything, "valid-token").Return(user, nil)
			},
			expectedStatus: http.StatusOK,
			checkContext: func(t *testing.T, r *http.Request) {
				user := GetUserFromContext(r.Context())
				assert.NotNil(t, user)
				assert.Equal(t, "user123", user.ID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAuth := new(MockAuthService)
			if tt.mockSetup != nil {
				tt.mockSetup(mockAuth)
			}

			// Create test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.checkContext != nil {
					tt.checkContext(t, r)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			// Apply middleware
			middleware := OptionalAuth(mockAuth, logger)
			wrappedHandler := middleware(handler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Execute request
			w := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestGetUserFromContext(t *testing.T) {
	tests := []struct {
		name         string
		contextValue interface{}
		expectedUser *auth.User
	}{
		{
			name:         "no user in context",
			contextValue: nil,
			expectedUser: nil,
		},
		{
			name:         "wrong type in context",
			contextValue: "not a user",
			expectedUser: nil,
		},
		{
			name: "valid user in context",
			contextValue: &auth.User{
				ID:       "user123",
				Username: "testuser",
			},
			expectedUser: &auth.User{
				ID:       "user123",
				Username: "testuser",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.contextValue != nil {
				ctx = context.WithValue(ctx, userContextKey, tt.contextValue)
			}

			user := GetUserFromContext(ctx)
			assert.Equal(t, tt.expectedUser, user)
		})
	}
}

func TestRequireAuth(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		user           *auth.User
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "no user - unauthorized",
			user:           nil,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Authentication required",
		},
		{
			name: "user present - authorized",
			user: &auth.User{
				ID:       "user123",
				Username: "testuser",
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "success",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("success"))
			})

			// Apply middleware
			middleware := RequireAuth(logger)
			wrappedHandler := middleware(handler)

			// Create request
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.user != nil {
				ctx := context.WithValue(req.Context(), userContextKey, tt.user)
				req = req.WithContext(ctx)
			}

			// Execute request
			w := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)
		})
	}
}

func TestAdminOnly(t *testing.T) {
	logger := utils.NewLogger("", false)

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("admin access"))
	})

	// Apply middleware
	middleware := AdminOnly(logger)
	wrappedHandler := middleware(handler)

	// Test with admin user
	adminUser := &auth.User{
		ID:   "admin123",
		Role: auth.RoleAdmin,
	}
	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	ctx := context.WithValue(req.Context(), userContextKey, adminUser)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "admin access", w.Body.String())
}

func TestUserOrAdmin(t *testing.T) {
	logger := utils.NewLogger("", false)

	// Create test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("user access"))
	})

	// Apply middleware
	middleware := UserOrAdmin(logger)
	wrappedHandler := middleware(handler)

	// Test with regular user
	user := &auth.User{
		ID:   "user123",
		Role: auth.RoleUser,
	}
	req := httptest.NewRequest(http.MethodGet, "/user", nil)
	ctx := context.WithValue(req.Context(), userContextKey, user)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user access", w.Body.String())
}