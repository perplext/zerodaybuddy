package auth

import (
	"context"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_HasPermission(t *testing.T) {
	tests := []struct {
		name       string
		user       *User
		permission UserRole
		expected   bool
	}{
		{
			name: "Admin has admin permissions",
			user: &User{Role: RoleAdmin},
			permission: RoleAdmin,
			expected: true,
		},
		{
			name: "Admin has user permissions",
			user: &User{Role: RoleAdmin},
			permission: RoleUser,
			expected: true,
		},
		{
			name: "Admin has readonly permissions",
			user: &User{Role: RoleAdmin},
			permission: RoleReadOnly,
			expected: true,
		},
		{
			name: "User has user permissions",
			user: &User{Role: RoleUser},
			permission: RoleUser,
			expected: true,
		},
		{
			name: "User has readonly permissions",
			user: &User{Role: RoleUser},
			permission: RoleReadOnly,
			expected: true,
		},
		{
			name: "User lacks admin permissions",
			user: &User{Role: RoleUser},
			permission: RoleAdmin,
			expected: false,
		},
		{
			name: "ReadOnly has readonly permissions",
			user: &User{Role: RoleReadOnly},
			permission: RoleReadOnly,
			expected: true,
		},
		{
			name: "ReadOnly lacks user permissions",
			user: &User{Role: RoleReadOnly},
			permission: RoleUser,
			expected: false,
		},
		{
			name: "ReadOnly lacks admin permissions",
			user: &User{Role: RoleReadOnly},
			permission: RoleAdmin,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.user.HasPermission(tt.permission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSession_IsExpired(t *testing.T) {
	now := time.Now()
	
	tests := []struct {
		name     string
		session  *Session
		expected bool
	}{
		{
			name: "expires in future",
			session: &Session{
				ExpiresAt: now.Add(time.Hour),
			},
			expected: false,
		},
		{
			name: "expired in past",
			session: &Session{
				ExpiresAt: now.Add(-time.Hour),
			},
			expected: true,
		},
		{
			name: "expires now (considered expired)",
			session: &Session{
				ExpiresAt: now.Add(-time.Millisecond),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.session.IsExpired()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAuthService_RefreshToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Create a test user
	createReq := &CreateUserRequest{
		Username: "refreshtest",
		Email:    "refresh@example.com",
		FullName: "Refresh Test",
		Password: "SecurePass123!",
		Role:     RoleUser,
	}
	user, err := service.CreateUser(context.Background(), createReq)
	require.NoError(t, err)

	// Generate a refresh token directly using the token manager
	tokens, err := service.tokenManager.GenerateTokenPair(user)
	require.NoError(t, err)

	tests := []struct {
		name        string
		token       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid refresh token",
			token:       tokens.RefreshToken,
			expectError: false,
		},
		{
			name:        "invalid refresh token",
			token:       "invalid.refresh.token",
			expectError: true,
			errorMsg:    "invalid",
		},
		{
			name:        "empty refresh token",
			token:       "",
			expectError: true,
			errorMsg:    "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.RefreshToken(context.Background(), tt.token)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, response)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, response)
				assert.NotEmpty(t, response.Token)
				assert.Equal(t, user.Username, response.User.Username)
			}
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Create and login a user
	createReq := &CreateUserRequest{
		Username: "logouttest",
		Email:    "logout@example.com",
		FullName: "Logout Test",
		Password: "SecurePass123!",
		Role:     RoleUser,
	}
	_, err := service.CreateUser(context.Background(), createReq)
	require.NoError(t, err)

	loginReq := &LoginRequest{
		Username: "logouttest",
		Password: "SecurePass123!",
	}
	loginResp, err := service.Login(context.Background(), loginReq, "127.0.0.1", "test-agent")
	require.NoError(t, err)

	// Test logout
	err = service.Logout(context.Background(), loginResp.Token)
	assert.NoError(t, err)

	// Test logout with invalid token (should not error)
	err = service.Logout(context.Background(), "invalid-token")
	assert.NoError(t, err)
}

func TestAuthService_GetUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Create a test user
	createReq := &CreateUserRequest{
		Username: "gettest",
		Email:    "get@example.com",
		FullName: "Get Test",
		Password: "SecurePass123!",
		Role:     RoleUser,
	}
	createdUser, err := service.CreateUser(context.Background(), createReq)
	require.NoError(t, err)

	// Test getting existing user
	user, err := service.GetUser(context.Background(), createdUser.ID)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, createdUser.ID, user.ID)
	assert.Equal(t, createdUser.Username, user.Username)
	assert.Equal(t, createdUser.Email, user.Email)
	assert.Empty(t, user.Password) // Password should not be returned

	// Test getting non-existent user
	_, err = service.GetUser(context.Background(), "non-existent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user")
}

func TestAuthService_ListUsers(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Create multiple test users
	users := []CreateUserRequest{
		{
			Username: "listuser1",
			Email:    "list1@example.com",
			FullName: "List User 1",
			Password: "SecurePass123!",
			Role:     RoleUser,
		},
		{
			Username: "listuser2",
			Email:    "list2@example.com",
			FullName: "List User 2",
			Password: "SecurePass123!",
			Role:     RoleAdmin,
		},
	}

	for _, req := range users {
		_, err := service.CreateUser(context.Background(), &req)
		require.NoError(t, err)
	}

	// Test listing users
	userList, err := service.ListUsers(context.Background())
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(userList), 2)

	// Verify no passwords are returned
	for _, user := range userList {
		assert.Empty(t, user.Password)
	}
}

func TestAuthService_DeleteUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Create a test user
	createReq := &CreateUserRequest{
		Username: "deletetest",
		Email:    "delete@example.com",
		FullName: "Delete Test",
		Password: "SecurePass123!",
		Role:     RoleUser,
	}
	user, err := service.CreateUser(context.Background(), createReq)
	require.NoError(t, err)

	// Test deleting existing user
	err = service.DeleteUser(context.Background(), user.ID)
	assert.NoError(t, err)

	// Verify user is deleted
	_, err = service.GetUser(context.Background(), user.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get user")

	// Test deleting non-existent user
	err = service.DeleteUser(context.Background(), "non-existent-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user not found")
}

func TestAuthService_CleanupExpiredSessions(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Test cleanup (this mainly tests that the function doesn't error)
	err := service.CleanupExpiredSessions(context.Background())
	assert.NoError(t, err)
}

func TestExtractIPAddress(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		xForwardedFor  string
		xRealIP        string
		proxyEnabled   bool
		expected       string
	}{
		{
			name:       "direct IP with port",
			remoteAddr: "192.168.1.100:8080",
			expected:   "192.168.1.100",
		},
		{
			name:       "direct IP without port",
			remoteAddr: "192.168.1.100",
			expected:   "192.168.1.100",
		},
		{
			name:          "X-Forwarded-For trusted when proxy enabled",
			remoteAddr:    "127.0.0.1:8080",
			xForwardedFor: "203.0.113.195, 70.41.3.18, 150.172.238.178",
			proxyEnabled:  true,
			expected:      "150.172.238.178", // rightmost valid IP
		},
		{
			name:          "X-Forwarded-For ignored when proxy disabled",
			remoteAddr:    "127.0.0.1:8080",
			xForwardedFor: "203.0.113.195",
			proxyEnabled:  false,
			expected:      "127.0.0.1",
		},
		{
			name:         "X-Real-IP trusted when proxy enabled",
			remoteAddr:   "127.0.0.1:8080",
			xRealIP:      "203.0.113.195",
			proxyEnabled: true,
			expected:     "203.0.113.195",
		},
		{
			name:         "X-Real-IP ignored when proxy disabled",
			remoteAddr:   "127.0.0.1:8080",
			xRealIP:      "203.0.113.195",
			proxyEnabled: false,
			expected:     "127.0.0.1",
		},
		{
			name:          "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr:    "127.0.0.1:8080",
			xForwardedFor: "203.0.113.195",
			xRealIP:       "10.0.0.1",
			proxyEnabled:  true,
			expected:      "203.0.113.195",
		},
		{
			name:          "invalid X-Forwarded-For falls back to X-Real-IP",
			remoteAddr:    "127.0.0.1:8080",
			xForwardedFor: "invalid-ip",
			xRealIP:       "203.0.113.195",
			proxyEnabled:  true,
			expected:      "203.0.113.195",
		},
		{
			name:          "invalid headers fall back to RemoteAddr",
			remoteAddr:    "192.168.1.100:8080",
			xForwardedFor: "invalid-ip",
			xRealIP:       "also-invalid",
			proxyEnabled:  true,
			expected:      "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExtractIPAddress(tt.remoteAddr, tt.xForwardedFor, tt.xRealIP, tt.proxyEnabled)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSQLStore_UpdateUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)

	// Create a user first
	user := &User{
		ID:       "test-update-id",
		Username: "updatetest",
		Email:    "update@example.com",
		FullName: "Update Test",
		Password: "hashedpassword",
		Role:     RoleUser,
		Status:   StatusActive,
	}

	err := store.CreateUser(context.Background(), user)
	require.NoError(t, err)

	// Update the user
	user.FullName = "Updated Name"
	user.Email = "updated@example.com"
	user.Role = RoleAdmin

	err = store.UpdateUser(context.Background(), user)
	assert.NoError(t, err)

	// Verify the update
	updatedUser, err := store.GetUser(context.Background(), user.ID)
	assert.NoError(t, err)
	assert.Equal(t, "Updated Name", updatedUser.FullName)
	assert.Equal(t, "updated@example.com", updatedUser.Email)
	assert.Equal(t, RoleAdmin, updatedUser.Role)
}

func TestSQLStore_GetSession(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)

	// Create a user first
	user := &User{
		ID:       "test-session-user",
		Username: "sessiontest",
		Email:    "session@example.com",
		FullName: "Session Test",
		Password: "hashedpassword",
		Role:     RoleUser,
		Status:   StatusActive,
	}

	err := store.CreateUser(context.Background(), user)
	require.NoError(t, err)

	// Create a session
	session := &Session{
		ID:        "test-session-id",
		UserID:    user.ID,
		Token:     "test-session-token",
		ExpiresAt: time.Now().Add(time.Hour),
		IPAddress: "127.0.0.1",
		UserAgent: "test-agent",
	}

	err = store.CreateSession(context.Background(), session)
	require.NoError(t, err)

	// Test getting existing session
	retrievedSession, err := store.GetSession(context.Background(), session.Token)
	assert.NoError(t, err)
	assert.NotNil(t, retrievedSession)
	assert.Equal(t, session.ID, retrievedSession.ID)
	assert.Equal(t, session.Token, retrievedSession.Token)
	assert.Equal(t, session.UserID, retrievedSession.UserID)

	// Test getting non-existent session
	_, err = store.GetSession(context.Background(), "non-existent-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestGenerateSessionToken(t *testing.T) {
	token, err := GenerateSessionToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Greater(t, len(token), 32) // Should be reasonably long

	// Generate another token to ensure they're different
	token2, err := GenerateSessionToken()
	assert.NoError(t, err)
	assert.NotEqual(t, token, token2)
}

func TestGenerateCSRFToken(t *testing.T) {
	token, err := GenerateCSRFToken()
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Greater(t, len(token), 16) // Should be reasonably long

	// Generate another token to ensure they're different
	token2, err := GenerateCSRFToken()
	assert.NoError(t, err)
	assert.NotEqual(t, token, token2)
}