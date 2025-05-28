package auth

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Store defines the interface for auth storage operations
type Store interface {
	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	UpdateUserPassword(ctx context.Context, userID, passwordHash string) error
	UpdateUserLastLogin(ctx context.Context, userID string) error
	ListUsers(ctx context.Context) ([]*User, error)
	DeleteUser(ctx context.Context, id string) error

	// Session operations
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, token string) (*Session, error)
	DeleteSession(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CleanupExpiredSessions(ctx context.Context) error
}

// SQLStore implements auth storage using SQLite
type SQLStore struct {
	db *sqlx.DB
}

// NewSQLStore creates a new SQL auth store
func NewSQLStore(db *sqlx.DB) *SQLStore {
	return &SQLStore{db: db}
}

// CreateUser creates a new user
func (s *SQLStore) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}

	if user.CreatedAt.IsZero() {
		user.CreatedAt = utils.CurrentTime()
	}
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = utils.CurrentTime()
	}

	// Set default values
	if user.Role == "" {
		user.Role = RoleUser
	}
	if user.Status == "" {
		user.Status = StatusActive
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (
			id, username, email, full_name, password_hash, role, status, 
			last_login, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		user.ID, user.Username, user.Email, user.FullName, user.Password,
		user.Role, user.Status, user.LastLogin, user.CreatedAt, user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetUser retrieves a user by ID
func (s *SQLStore) GetUser(ctx context.Context, id string) (*User, error) {
	var user User
	err := s.db.GetContext(ctx, &user, `
		SELECT id, username, email, full_name, password_hash, role, status,
			   last_login, created_at, updated_at
		FROM users WHERE id = ?
	`, id)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &user, nil
}

// GetUserByUsername retrieves a user by username
func (s *SQLStore) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	err := s.db.GetContext(ctx, &user, `
		SELECT id, username, email, full_name, password_hash, role, status,
			   last_login, created_at, updated_at
		FROM users WHERE username = ?
	`, username)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by username: %w", err)
	}

	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (s *SQLStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := s.db.GetContext(ctx, &user, `
		SELECT id, username, email, full_name, password_hash, role, status,
			   last_login, created_at, updated_at
		FROM users WHERE email = ?
	`, email)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user by email: %w", err)
	}

	return &user, nil
}

// UpdateUser updates a user
func (s *SQLStore) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = utils.CurrentTime()

	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET
			username = ?, email = ?, full_name = ?, role = ?, status = ?,
			last_login = ?, updated_at = ?
		WHERE id = ?
	`,
		user.Username, user.Email, user.FullName, user.Role, user.Status,
		user.LastLogin, user.UpdatedAt, user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// UpdateUserPassword updates a user's password
func (s *SQLStore) UpdateUserPassword(ctx context.Context, userID, passwordHash string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?
	`, passwordHash, utils.CurrentTime(), userID)

	if err != nil {
		return fmt.Errorf("failed to update user password: %w", err)
	}

	return nil
}

// UpdateUserLastLogin updates a user's last login time
func (s *SQLStore) UpdateUserLastLogin(ctx context.Context, userID string) error {
	now := utils.CurrentTime()
	_, err := s.db.ExecContext(ctx, `
		UPDATE users SET last_login = ?, updated_at = ? WHERE id = ?
	`, now, now, userID)

	if err != nil {
		return fmt.Errorf("failed to update user last login: %w", err)
	}

	return nil
}

// ListUsers lists all users
func (s *SQLStore) ListUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	err := s.db.SelectContext(ctx, &users, `
		SELECT id, username, email, full_name, password_hash, role, status,
			   last_login, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	return users, nil
}

// DeleteUser deletes a user
func (s *SQLStore) DeleteUser(ctx context.Context, id string) error {
	// Delete user sessions first
	if err := s.DeleteUserSessions(ctx, id); err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	_, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// CreateSession creates a new session
func (s *SQLStore) CreateSession(ctx context.Context, session *Session) error {
	if session.ID == "" {
		session.ID = uuid.New().String()
	}

	if session.CreatedAt.IsZero() {
		session.CreatedAt = utils.CurrentTime()
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token, expires_at, ip_address, user_agent, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		session.ID, session.UserID, session.Token, session.ExpiresAt,
		session.IPAddress, session.UserAgent, session.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}

	return nil
}

// GetSession retrieves a session by token
func (s *SQLStore) GetSession(ctx context.Context, token string) (*Session, error) {
	var session Session
	err := s.db.GetContext(ctx, &session, `
		SELECT id, user_id, token, expires_at, ip_address, user_agent, created_at
		FROM sessions WHERE token = ?
	`, token)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	return &session, nil
}

// DeleteSession deletes a session by token
func (s *SQLStore) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token = ?", token)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

// DeleteUserSessions deletes all sessions for a user
func (s *SQLStore) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete user sessions: %w", err)
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions
func (s *SQLStore) CleanupExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ?", time.Now())
	if err != nil {
		return fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	return nil
}