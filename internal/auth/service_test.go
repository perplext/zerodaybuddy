package auth

import (
	"context"
	"testing"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func setupTestDB(t *testing.T) *sqlx.DB {
	db, err := sqlx.Connect("sqlite", ":memory:")
	require.NoError(t, err)

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			email TEXT NOT NULL UNIQUE,
			full_name TEXT NOT NULL,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			status TEXT NOT NULL DEFAULT 'active',
			last_login TIMESTAMP,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);

		CREATE TABLE sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			expires_at TIMESTAMP NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			created_at TIMESTAMP NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		);
	`)
	require.NoError(t, err)

	return db
}

func TestAuthService_CreateUser(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	tests := []struct {
		name        string
		req         *CreateUserRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid user creation",
			req: &CreateUserRequest{
				Username: "testuser",
				Email:    "test@example.com",
				FullName: "Test User",
				Password: "SecurePass123!",
				Role:     RoleUser,
			},
			expectError: false,
		},
		{
			name: "weak password",
			req: &CreateUserRequest{
				Username: "testuser2",
				Email:    "test2@example.com",
				FullName: "Test User 2",
				Password: "weak",
				Role:     RoleUser,
			},
			expectError: true,
			errorMsg:    "password validation failed",
		},
		{
			name: "duplicate username",
			req: &CreateUserRequest{
				Username: "testuser", // Same as first test
				Email:    "different@example.com",
				FullName: "Different User",
				Password: "SecurePass123!",
				Role:     RoleUser,
			},
			expectError: true,
			errorMsg:    "username already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := service.CreateUser(context.Background(), tt.req)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, user)
				assert.Equal(t, tt.req.Username, user.Username)
				assert.Equal(t, tt.req.Email, user.Email)
				assert.Equal(t, tt.req.FullName, user.FullName)
				assert.Empty(t, user.Password) // Password should not be returned
				assert.Equal(t, tt.req.Role, user.Role)
				assert.Equal(t, StatusActive, user.Status)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Create a test user
	createReq := &CreateUserRequest{
		Username: "logintest",
		Email:    "login@example.com",
		FullName: "Login Test",
		Password: "SecurePass123!",
		Role:     RoleUser,
	}
	_, err := service.CreateUser(context.Background(), createReq)
	require.NoError(t, err)

	tests := []struct {
		name        string
		req         *LoginRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid login",
			req: &LoginRequest{
				Username: "logintest",
				Password: "SecurePass123!",
			},
			expectError: false,
		},
		{
			name: "invalid password",
			req: &LoginRequest{
				Username: "logintest",
				Password: "wrongpassword",
			},
			expectError: true,
			errorMsg:    "invalid credentials",
		},
		{
			name: "non-existent user",
			req: &LoginRequest{
				Username: "nonexistent",
				Password: "SecurePass123!",
			},
			expectError: true,
			errorMsg:    "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.Login(context.Background(), tt.req, "127.0.0.1", "test-agent")

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
				assert.Equal(t, tt.req.Username, response.User.Username)
				assert.Empty(t, response.User.Password) // Password should not be returned
			}
		})
	}
}

func TestAuthService_ValidateToken(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Create and login a user to get a token
	createReq := &CreateUserRequest{
		Username: "tokentest",
		Email:    "token@example.com",
		FullName: "Token Test",
		Password: "SecurePass123!",
		Role:     RoleUser,
	}
	user, err := service.CreateUser(context.Background(), createReq)
	require.NoError(t, err)

	loginReq := &LoginRequest{
		Username: "tokentest",
		Password: "SecurePass123!",
	}
	response, err := service.Login(context.Background(), loginReq, "127.0.0.1", "test-agent")
	require.NoError(t, err)

	tests := []struct {
		name        string
		token       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid token",
			token:       response.Token,
			expectError: false,
		},
		{
			name:        "invalid token",
			token:       "invalid.token.here",
			expectError: true,
			errorMsg:    "invalid token",
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
			errorMsg:    "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validatedUser, err := service.ValidateToken(context.Background(), tt.token)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				assert.Nil(t, validatedUser)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validatedUser)
				assert.Equal(t, user.Username, validatedUser.Username)
				assert.Empty(t, validatedUser.Password) // Password should not be returned
			}
		})
	}
}

func TestAuthService_ChangePassword(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	store := NewSQLStore(db)
	logger := utils.NewLogger("", false)
	service := NewService(store, "test-secret", "test-issuer", logger)

	// Create a test user
	createReq := &CreateUserRequest{
		Username: "passtest",
		Email:    "pass@example.com",
		FullName: "Password Test",
		Password: "OldPass123!",
		Role:     RoleUser,
	}
	user, err := service.CreateUser(context.Background(), createReq)
	require.NoError(t, err)

	tests := []struct {
		name        string
		req         *ChangePasswordRequest
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid password change",
			req: &ChangePasswordRequest{
				CurrentPassword: "OldPass123!",
				NewPassword:     "NewPass123!",
			},
			expectError: false,
		},
		{
			name: "wrong current password",
			req: &ChangePasswordRequest{
				CurrentPassword: "WrongPass123!",
				NewPassword:     "NewPass123!",
			},
			expectError: true,
			errorMsg:    "current password is incorrect",
		},
		{
			name: "weak new password",
			req: &ChangePasswordRequest{
				CurrentPassword: "NewPass123!", // Note: this test runs after password was already changed
				NewPassword:     "weak",
			},
			expectError: true,
			errorMsg:    "password validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ChangePassword(context.Background(), user.ID, tt.req)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPasswordHashing(t *testing.T) {
	password := "TestPassword123!"

	// Test hashing
	hash, err := HashPassword(password)
	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Contains(t, hash, "$argon2id$")

	// Test verification with correct password
	valid, err := VerifyPassword(password, hash)
	assert.NoError(t, err)
	assert.True(t, valid)

	// Test verification with wrong password
	valid, err = VerifyPassword("WrongPassword", hash)
	assert.NoError(t, err)
	assert.False(t, valid)
}

func TestPasswordValidation(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{"valid password", "SecurePass123!", false},
		{"too short", "Sh0rt!", true},
		{"no uppercase", "securepass123!", true},
		{"no lowercase", "SECUREPASS123!", true},
		{"no digit", "SecurePassword!", true},
		{"no special char", "SecurePass123", true},
		{"common weak password", "password123", true},
		{"too long", string(make([]byte, 130)), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTokenManager(t *testing.T) {
	tm := NewTokenManager("test-secret", "test-issuer")

	user := &User{
		ID:       "test-user-id",
		Username: "testuser",
		Role:     RoleUser,
	}

	// Test token generation
	tokens, err := tm.GenerateTokenPair(user)
	assert.NoError(t, err)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.Greater(t, tokens.ExpiresIn, int64(0))

	// Test access token validation
	claims, err := tm.ValidateToken(tokens.AccessToken)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Username, claims.Username)
	assert.Equal(t, user.Role, claims.Role)
	assert.Equal(t, "access", claims.Type)

	// Test refresh token validation
	claims, err = tm.ValidateToken(tokens.RefreshToken)
	assert.NoError(t, err)
	assert.Equal(t, "refresh", claims.Type)

	// Test token refresh
	time.Sleep(time.Second) // Delay to ensure different timestamp
	newTokens, err := tm.RefreshTokens(tokens.RefreshToken, user)
	assert.NoError(t, err)
	assert.NotEmpty(t, newTokens.AccessToken)
	assert.NotEmpty(t, newTokens.RefreshToken)
	
	// Verify the new access token is valid
	newClaims, err := tm.ValidateToken(newTokens.AccessToken)
	assert.NoError(t, err)
	assert.Equal(t, user.ID, newClaims.UserID)
	assert.Equal(t, "access", newClaims.Type)
}