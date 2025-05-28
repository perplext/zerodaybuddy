package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuthService is a mock implementation of the auth service
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) Login(ctx context.Context, req *auth.LoginRequest, ipAddress, userAgent string) (*auth.AuthResponse, error) {
	args := m.Called(ctx, req, ipAddress, userAgent)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.AuthResponse), args.Error(1)
}

func (m *MockAuthService) CreateUser(ctx context.Context, req *auth.CreateUserRequest) (*auth.User, error) {
	args := m.Called(ctx, req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.User), args.Error(1)
}

func (m *MockAuthService) Logout(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, refreshToken string) (*auth.TokenPair, error) {
	args := m.Called(ctx, refreshToken)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*auth.TokenPair), args.Error(1)
}

func (m *MockAuthService) ChangePassword(ctx context.Context, userID string, req *auth.ChangePasswordRequest) error {
	args := m.Called(ctx, userID, req)
	return args.Error(0)
}

func TestNewAuthHandler(t *testing.T) {
	logger := utils.NewLogger("", false)
	
	// Create a minimal auth service
	mockStore := &mockAuthStore{}
	authService := auth.NewService(mockStore, "test-secret", "test-issuer", logger)

	handler := NewAuthHandler(authService, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, authService, handler.authService)
	assert.Equal(t, logger, handler.logger)
}

// mockAuthStore implements the minimal Store interface needed for tests
type mockAuthStore struct{}

func (m *mockAuthStore) GetUserByUsername(ctx context.Context, username string) (*auth.User, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthStore) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthStore) CreateUser(ctx context.Context, user *auth.User) error {
	return errors.New("not implemented")
}

func (m *mockAuthStore) UpdateUser(ctx context.Context, user *auth.User) error {
	return errors.New("not implemented")
}


func (m *mockAuthStore) CreateSession(ctx context.Context, session *auth.Session) error {
	return errors.New("not implemented")
}

func (m *mockAuthStore) GetSession(ctx context.Context, token string) (*auth.Session, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthStore) DeleteExpiredSessions(ctx context.Context) error {
	return errors.New("not implemented")
}

func (m *mockAuthStore) GetUser(ctx context.Context, id string) (*auth.User, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthStore) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	return errors.New("not implemented")
}

func (m *mockAuthStore) UpdateUserLastLogin(ctx context.Context, userID string) error {
	return errors.New("not implemented")
}

func (m *mockAuthStore) ListUsers(ctx context.Context) ([]*auth.User, error) {
	return nil, errors.New("not implemented")
}

func (m *mockAuthStore) DeleteUser(ctx context.Context, id string) error {
	return errors.New("not implemented")
}

func (m *mockAuthStore) DeleteSession(ctx context.Context, token string) error {
	return errors.New("not implemented")
}

func (m *mockAuthStore) DeleteUserSessions(ctx context.Context, userID string) error {
	return errors.New("not implemented")
}

func (m *mockAuthStore) CleanupExpiredSessions(ctx context.Context) error {
	return errors.New("not implemented")
}

func TestAuthHandler_Login(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		method         string
		body           interface{}
		mockSetup      func(*testing.T) *auth.Service
		expectedStatus int
		expectedBody   string
		checkResponse  func(t *testing.T, body []byte)
	}{
		{
			name:           "wrong method",
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "invalid JSON",
			method:         http.MethodPost,
			body:           "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid JSON",
		},
		{
			name:   "empty username",
			method: http.MethodPost,
			body: auth.LoginRequest{
				Username: "",
				Password: "password123",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Username and password are required",
		},
		{
			name:   "empty password",
			method: http.MethodPost,
			body: auth.LoginRequest{
				Username: "testuser",
				Password: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Username and password are required",
		},
		{
			name:   "username too long",
			method: http.MethodPost,
			body: auth.LoginRequest{
				Username: "verylongusernamethatexceedsthemaximumlengthallowedbythevalidation",
				Password: "password123",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Username too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authService *auth.Service
			if tt.mockSetup != nil {
				authService = tt.mockSetup(t)
			} else {
				// Create a minimal auth service
				mockStore := &mockAuthStore{}
				authService = auth.NewService(mockStore, "test-secret", "test-issuer", logger)
			}

			handler := NewAuthHandler(authService, logger)

			// Prepare request body
			var bodyReader io.Reader
			if tt.body != nil {
				if str, ok := tt.body.(string); ok {
					bodyReader = bytes.NewReader([]byte(str))
				} else {
					bodyBytes, _ := json.Marshal(tt.body)
					bodyReader = bytes.NewReader(bodyBytes)
				}
			} else {
				bodyReader = bytes.NewReader([]byte{})
			}

			// Create request
			req := httptest.NewRequest(tt.method, "/login", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			// Execute request
			w := httptest.NewRecorder()
			handler.Login(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}
			if tt.checkResponse != nil {
				tt.checkResponse(t, w.Body.Bytes())
			}
		})
	}
}

func TestAuthHandler_Register(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		method         string
		body           interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "wrong method",
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "invalid JSON",
			method:         http.MethodPost,
			body:           "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid JSON",
		},
		{
			name:   "invalid username",
			method: http.MethodPost,
			body: auth.CreateUserRequest{
				Username: "a",
				Email:    "test@example.com",
				FullName: "Test User",
				Password: "Password123!",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "username must be at least 3 characters",
		},
		{
			name:   "invalid email",
			method: http.MethodPost,
			body: auth.CreateUserRequest{
				Username: "testuser",
				Email:    "invalid-email",
				FullName: "Test User",
				Password: "Password123!",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "invalid email format",
		},
		{
			name:   "empty full name",
			method: http.MethodPost,
			body: auth.CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				FullName: "",
				Password: "Password123!",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Full name is required",
		},
		{
			name:   "weak password",
			method: http.MethodPost,
			body: auth.CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				FullName: "Test User",
				Password: "weak",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "password must be at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal auth service
			mockStore := &mockAuthStore{}
			authService := auth.NewService(mockStore, "test-secret", "test-issuer", logger)
			handler := NewAuthHandler(authService, logger)

			// Prepare request body
			var bodyReader io.Reader
			if tt.body != nil {
				if str, ok := tt.body.(string); ok {
					bodyReader = bytes.NewReader([]byte(str))
				} else {
					bodyBytes, _ := json.Marshal(tt.body)
					bodyReader = bytes.NewReader(bodyBytes)
				}
			} else {
				bodyReader = bytes.NewReader([]byte{})
			}

			// Create request
			req := httptest.NewRequest(tt.method, "/register", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			// Execute request
			w := httptest.NewRecorder()
			handler.Register(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}
		})
	}
}

func TestAuthHandler_Profile(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		method         string
		user           *auth.User
		expectedStatus int
		expectedBody   string
		checkResponse  func(t *testing.T, body []byte)
	}{
		{
			name:           "wrong method",
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "not authenticated",
			method:         http.MethodGet,
			user:           nil,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Not authenticated",
		},
		{
			name:   "authenticated user",
			method: http.MethodGet,
			user: &auth.User{
				ID:       "user123",
				Username: "testuser",
				Email:    "test@example.com",
				FullName: "Test User",
				Role:     auth.RoleUser,
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body []byte) {
				var user auth.User
				err := json.Unmarshal(body, &user)
				require.NoError(t, err)
				assert.Equal(t, "user123", user.ID)
				assert.Equal(t, "testuser", user.Username)
				assert.Equal(t, "test@example.com", user.Email)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal auth service
			mockStore := &mockAuthStore{}
			authService := auth.NewService(mockStore, "test-secret", "test-issuer", logger)
			handler := NewAuthHandler(authService, logger)

			// Create request
			req := httptest.NewRequest(tt.method, "/profile", nil)
			if tt.user != nil {
				ctx := context.WithValue(req.Context(), "user", tt.user)
				req = req.WithContext(ctx)
			}

			// Execute request
			w := httptest.NewRecorder()
			handler.Profile(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			if tt.expectedBody != "" {
				assert.Contains(t, w.Body.String(), tt.expectedBody)
			}
			if tt.checkResponse != nil {
				tt.checkResponse(t, w.Body.Bytes())
			}
		})
	}
}

func TestAuthHandler_ChangePassword(t *testing.T) {
	logger := utils.NewLogger("", false)

	tests := []struct {
		name           string
		method         string
		user           *auth.User
		body           interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "wrong method",
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "not authenticated",
			method:         http.MethodPost,
			user:           nil,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "Not authenticated",
		},
		{
			name:           "invalid JSON",
			method:         http.MethodPost,
			user:           &auth.User{ID: "user123"},
			body:           "invalid json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid JSON",
		},
		{
			name:   "empty current password",
			method: http.MethodPost,
			user:   &auth.User{ID: "user123"},
			body: auth.ChangePasswordRequest{
				CurrentPassword: "",
				NewPassword:     "NewPassword123!",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Current and new passwords are required",
		},
		{
			name:   "weak new password",
			method: http.MethodPost,
			user:   &auth.User{ID: "user123"},
			body: auth.ChangePasswordRequest{
				CurrentPassword: "OldPassword123!",
				NewPassword:     "weak",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "password must be at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal auth service
			mockStore := &mockAuthStore{}
			authService := auth.NewService(mockStore, "test-secret", "test-issuer", logger)
			handler := NewAuthHandler(authService, logger)

			// Prepare request body
			var bodyReader io.Reader
			if tt.body != nil {
				if str, ok := tt.body.(string); ok {
					bodyReader = bytes.NewReader([]byte(str))
				} else {
					bodyBytes, _ := json.Marshal(tt.body)
					bodyReader = bytes.NewReader(bodyBytes)
				}
			} else {
				bodyReader = bytes.NewReader([]byte{})
			}

			// Create request
			req := httptest.NewRequest(tt.method, "/change-password", bodyReader)
			req.Header.Set("Content-Type", "application/json")
			if tt.user != nil {
				ctx := context.WithValue(req.Context(), "user", tt.user)
				req = req.WithContext(ctx)
			}

			// Execute request
			w := httptest.NewRecorder()
			handler.ChangePassword(w, req)

			// Assert
			assert.Equal(t, tt.expectedStatus, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectedBody)
		})
	}
}

func TestValidateCreateUserRequest(t *testing.T) {
	// Create a minimal auth service
	mockStore := &mockAuthStore{}
	authService := auth.NewService(mockStore, "test-secret", "test-issuer", utils.NewLogger("", false))
	handler := NewAuthHandler(authService, utils.NewLogger("", false))

	tests := []struct {
		name        string
		req         auth.CreateUserRequest
		expectedErr string
	}{
		{
			name: "valid request",
			req: auth.CreateUserRequest{
				Username: "validuser",
				Email:    "valid@example.com",
				FullName: "Valid User",
				Password: "Str0ng#Pass!2024",
			},
			expectedErr: "",
		},
		{
			name: "short username",
			req: auth.CreateUserRequest{
				Username: "ab",
				Email:    "valid@example.com",
				FullName: "Valid User",
				Password: "Str0ng#Pass!2024",
			},
			expectedErr: "username must be at least 3 characters",
		},
		{
			name: "invalid email",
			req: auth.CreateUserRequest{
				Username: "validuser",
				Email:    "notanemail",
				FullName: "Valid User",
				Password: "Str0ng#Pass!2024",
			},
			expectedErr: "invalid email format",
		},
		{
			name: "short full name",
			req: auth.CreateUserRequest{
				Username: "validuser",
				Email:    "valid@example.com",
				FullName: "A",
				Password: "Str0ng#Pass!2024",
			},
			expectedErr: "Full name must be between 2 and 100 characters",
		},
		{
			name: "weak password",
			req: auth.CreateUserRequest{
				Username: "validuser",
				Email:    "valid@example.com",
				FullName: "Valid User",
				Password: "123456",
			},
			expectedErr: "password must be at least 8 characters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateCreateUserRequest(&tt.req)
			if tt.expectedErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			}
		})
	}
}