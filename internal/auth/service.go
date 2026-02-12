package auth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/utils"
)

// Service provides authentication and authorization functionality
type Service struct {
	store        Store
	tokenManager *TokenManager
	logger       *utils.Logger
}

// NewService creates a new auth service
func NewService(store Store, jwtSecret, issuer string, logger *utils.Logger) *Service {
	return &Service{
		store:        store,
		tokenManager: NewTokenManager(jwtSecret, issuer),
		logger:       logger,
	}
}

// CreateUser creates a new user with password validation and hashing
func (s *Service) CreateUser(ctx context.Context, req *CreateUserRequest) (*User, error) {
	// Validate password strength
	if err := ValidatePassword(req.Password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Check if username already exists
	if _, err := s.store.GetUserByUsername(ctx, req.Username); err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Check if email already exists
	if _, err := s.store.GetUserByEmail(ctx, req.Email); err == nil {
		return nil, fmt.Errorf("email already exists")
	}

	// Hash password
	passwordHash, err := HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Always assign RoleUser for self-registration.
	// Only admins can assign roles via a separate admin endpoint.
	user := &User{
		Username: req.Username,
		Email:    req.Email,
		FullName: req.FullName,
		Password: passwordHash,
		Role:     RoleUser,
		Status:   StatusActive,
	}

	if err := s.store.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Don't return password hash
	user.Password = ""

	s.logger.Info("User created: %s (%s)", user.Username, user.Email)
	return user, nil
}

// Login authenticates a user and returns tokens
func (s *Service) Login(ctx context.Context, req *LoginRequest, ipAddress, userAgent string) (*AuthResponse, error) {
	// Get user by username
	user, err := s.store.GetUserByUsername(ctx, req.Username)
	if err != nil {
		s.logger.Warn("Login attempt for non-existent user: %s from %s", req.Username, ipAddress)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user can login
	if !user.CanLogin() {
		s.logger.Warn("Login attempt for inactive/locked user: %s from %s", req.Username, ipAddress)
		return nil, fmt.Errorf("account is inactive or locked")
	}

	// Verify password
	valid, err := VerifyPassword(req.Password, user.Password)
	if err != nil {
		s.logger.Error("Password verification error for user %s", req.Username)
		return nil, fmt.Errorf("authentication failed")
	}

	if !valid {
		s.logger.Warn("Invalid password attempt for user: %s from %s", req.Username, ipAddress)
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate token pair
	tokens, err := s.tokenManager.GenerateTokenPair(user)
	if err != nil {
		s.logger.Error("Failed to generate tokens for user %s: %v", req.Username, err)
		return nil, fmt.Errorf("failed to generate tokens")
	}

	// Create session record
	session := &Session{
		UserID:    user.ID,
		Token:     tokens.AccessToken,
		ExpiresAt: time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.store.CreateSession(ctx, session); err != nil {
		s.logger.Error("Failed to create session for user %s: %v", req.Username, err)
		// Don't fail login if session creation fails
	}

	// Update last login time
	if err := s.store.UpdateUserLastLogin(ctx, user.ID); err != nil {
		s.logger.Error("Failed to update last login for user %s: %v", req.Username, err)
		// Don't fail login if last login update fails
	}

	// Don't return password hash
	user.Password = ""

	s.logger.Info("User logged in: %s from %s", user.Username, ipAddress)

	return &AuthResponse{
		User:  user,
		Token: tokens.AccessToken,
	}, nil
}

// ValidateToken validates a JWT token and returns the user
func (s *Service) ValidateToken(ctx context.Context, tokenString string) (*User, error) {
	// Parse and validate token
	claims, err := s.tokenManager.ValidateToken(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Ensure it's an access token
	if claims.Type != "access" {
		return nil, fmt.Errorf("invalid token type")
	}

	// Verify session still exists (ensures logout actually revokes access)
	if _, err := s.store.GetSession(ctx, tokenString); err != nil {
		return nil, fmt.Errorf("session revoked")
	}

	// Get user from database
	user, err := s.store.GetUser(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if user is still active
	if !user.CanLogin() {
		return nil, fmt.Errorf("user account is inactive")
	}

	// Don't return password hash
	user.Password = ""

	return user, nil
}

// RefreshToken generates new tokens using a refresh token
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	// Validate refresh token
	claims, err := s.tokenManager.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Ensure it's a refresh token
	if claims.Type != "refresh" {
		return nil, fmt.Errorf("invalid token type")
	}

	// Get user
	user, err := s.store.GetUser(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if user is still active
	if !user.CanLogin() {
		return nil, fmt.Errorf("user account is inactive")
	}

	// Generate new token pair
	tokens, err := s.tokenManager.GenerateTokenPair(user)
	if err != nil {
		return nil, fmt.Errorf("failed to generate tokens: %w", err)
	}

	// Don't return password hash
	user.Password = ""

	return &AuthResponse{
		User:  user,
		Token: tokens.AccessToken,
	}, nil
}

// Logout invalidates a session
func (s *Service) Logout(ctx context.Context, token string) error {
	// Try to delete the session
	if err := s.store.DeleteSession(ctx, token); err != nil {
		s.logger.Warn("Failed to delete session during logout: %v", err)
		// Don't fail logout if session deletion fails
	}

	return nil
}

// ChangePassword changes a user's password
func (s *Service) ChangePassword(ctx context.Context, userID string, req *ChangePasswordRequest) error {
	// Get user
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Verify current password
	valid, err := VerifyPassword(req.CurrentPassword, user.Password)
	if err != nil {
		return fmt.Errorf("password verification failed")
	}

	if !valid {
		return fmt.Errorf("current password is incorrect")
	}

	// Validate new password
	if err := ValidatePassword(req.NewPassword); err != nil {
		return fmt.Errorf("new password validation failed: %w", err)
	}

	// Hash new password
	newPasswordHash, err := HashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to hash new password: %w", err)
	}

	// Update password
	if err := s.store.UpdateUserPassword(ctx, userID, newPasswordHash); err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	// Invalidate all user sessions
	if err := s.store.DeleteUserSessions(ctx, userID); err != nil {
		s.logger.Warn("Failed to invalidate user sessions after password change: %v", err)
	}

	s.logger.Info("Password changed for user: %s", user.Username)
	return nil
}

// GetUser retrieves a user by ID
func (s *Service) GetUser(ctx context.Context, userID string) (*User, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Don't return password hash
	user.Password = ""
	return user, nil
}

// ListUsers lists all users (admin only)
func (s *Service) ListUsers(ctx context.Context) ([]*User, error) {
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	// Remove password hashes
	for _, user := range users {
		user.Password = ""
	}

	return users, nil
}

// DeleteUser deletes a user (admin only)
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	// Get user for logging
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Delete user (this will also delete sessions via CASCADE)
	if err := s.store.DeleteUser(ctx, userID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.Info("User deleted: %s (%s)", user.Username, user.Email)
	return nil
}

// CleanupExpiredSessions removes expired sessions
func (s *Service) CleanupExpiredSessions(ctx context.Context) error {
	return s.store.CleanupExpiredSessions(ctx)
}

// ExtractIPAddress extracts IP address from request, considering proxies.
// Only trust proxy headers (X-Forwarded-For, X-Real-IP) when proxyEnabled is true.
func ExtractIPAddress(remoteAddr, xForwardedFor, xRealIP string, proxyEnabled bool) string {
	if proxyEnabled {
		// When behind a trusted reverse proxy, take the rightmost non-private IP
		// from X-Forwarded-For (closest to the proxy we trust).
		if xForwardedFor != "" {
			ips := strings.Split(xForwardedFor, ",")
			// Walk from right to left — the rightmost entry was appended by our proxy
			for i := len(ips) - 1; i >= 0; i-- {
				ip := strings.TrimSpace(ips[i])
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}

		// Check X-Real-IP header
		if xRealIP != "" {
			if net.ParseIP(xRealIP) != nil {
				return xRealIP
			}
		}
	}

	// Fall back to RemoteAddr (always trusted)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}

	return remoteAddr
}