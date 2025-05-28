package auth

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID        string    `json:"id" db:"id"`
	Username  string    `json:"username" db:"username"`
	Email     string    `json:"email" db:"email"`
	FullName  string    `json:"full_name" db:"full_name"`
	Password  string    `json:"-" db:"password_hash"` // Never serialize password
	Role      UserRole  `json:"role" db:"role"`
	Status    UserStatus `json:"status" db:"status"`
	LastLogin *time.Time `json:"last_login,omitempty" db:"last_login"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// UserRole represents user roles in the system
type UserRole string

const (
	RoleAdmin     UserRole = "admin"
	RoleUser      UserRole = "user"
	RoleReadOnly  UserRole = "readonly"
)

// UserStatus represents user account status
type UserStatus string

const (
	StatusActive   UserStatus = "active"
	StatusInactive UserStatus = "inactive"
	StatusLocked   UserStatus = "locked"
	StatusPending  UserStatus = "pending"
)

// Session represents a user session
type Session struct {
	ID        string    `json:"id" db:"id"`
	UserID    string    `json:"user_id" db:"user_id"`
	Token     string    `json:"token" db:"token"`
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	IPAddress string    `json:"ip_address" db:"ip_address"`
	UserAgent string    `json:"user_agent" db:"user_agent"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// CreateUserRequest represents a request to create a new user
type CreateUserRequest struct {
	Username string   `json:"username" validate:"required,min=3,max=50"`
	Email    string   `json:"email" validate:"required,email"`
	FullName string   `json:"full_name" validate:"required,min=2,max=100"`
	Password string   `json:"password" validate:"required,min=8"`
	Role     UserRole `json:"role,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// AuthResponse represents an authentication response
type AuthResponse struct {
	User  *User  `json:"user"`
	Token string `json:"token"`
}

// HasPermission checks if the user has the required role
func (u *User) HasPermission(requiredRole UserRole) bool {
	switch requiredRole {
	case RoleReadOnly:
		return u.Role == RoleReadOnly || u.Role == RoleUser || u.Role == RoleAdmin
	case RoleUser:
		return u.Role == RoleUser || u.Role == RoleAdmin
	case RoleAdmin:
		return u.Role == RoleAdmin
	default:
		return false
	}
}

// IsActive checks if the user account is active
func (u *User) IsActive() bool {
	return u.Status == StatusActive
}

// CanLogin checks if the user can log in
func (u *User) CanLogin() bool {
	return u.IsActive() && u.Status != StatusLocked
}

// IsExpired checks if a session is expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}