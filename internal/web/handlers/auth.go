package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/perplext/zerodaybuddy/internal/auth"
	"github.com/perplext/zerodaybuddy/internal/web/middleware"
	"github.com/perplext/zerodaybuddy/pkg/utils"
	"github.com/perplext/zerodaybuddy/pkg/validation"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	authService *auth.Service
	logger      *utils.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(authService *auth.Service, logger *utils.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      logger,
	}
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("Invalid JSON in login request: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate and sanitize input
	req.Username = validation.SanitizeString(req.Username)
	req.Password = validation.SanitizeString(req.Password)
	
	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}
	
	// Additional username validation (lenient for login)
	if len(req.Username) > 50 {
		http.Error(w, "Username too long", http.StatusBadRequest)
		return
	}

	// Extract client info
	ipAddress := auth.ExtractIPAddress(r.RemoteAddr, r.Header.Get("X-Forwarded-For"), r.Header.Get("X-Real-IP"))
	userAgent := r.Header.Get("User-Agent")

	// Attempt login
	response, err := h.authService.Login(r.Context(), &req, ipAddress, userAgent)
	if err != nil {
		h.logger.Debug("Login failed for %s: %v", req.Username, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Register handles user registration
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req auth.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("Invalid JSON in register request: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request
	if err := h.validateCreateUserRequest(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create user
	user, err := h.authService.CreateUser(r.Context(), &req)
	if err != nil {
		h.logger.Debug("User creation failed: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "No token provided", http.StatusBadRequest)
		return
	}

	// Parse Bearer token
	parts := authHeader[7:] // Remove "Bearer "
	if len(parts) == 0 {
		http.Error(w, "Invalid token format", http.StatusBadRequest)
		return
	}

	// Logout
	if err := h.authService.Logout(r.Context(), parts); err != nil {
		h.logger.Debug("Logout failed: %v", err)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out successfully"})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.RefreshToken == "" {
		http.Error(w, "Refresh token is required", http.StatusBadRequest)
		return
	}

	// Refresh tokens
	response, err := h.authService.RefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		h.logger.Debug("Token refresh failed: %v", err)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Profile returns the current user's profile
func (h *AuthHandler) Profile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// ChangePassword handles password change requests
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	var req auth.ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate passwords
	req.CurrentPassword = validation.SanitizeString(req.CurrentPassword)
	req.NewPassword = validation.SanitizeString(req.NewPassword)
	
	if req.CurrentPassword == "" || req.NewPassword == "" {
		http.Error(w, "Current and new passwords are required", http.StatusBadRequest)
		return
	}
	
	// Validate new password strength
	if err := validation.Password(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Change password
	if err := h.authService.ChangePassword(r.Context(), user.ID, &req); err != nil {
		h.logger.Debug("Password change failed for user %s: %v", user.Username, err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully"})
}

// validateCreateUserRequest validates user creation request
func (h *AuthHandler) validateCreateUserRequest(req *auth.CreateUserRequest) error {
	// Sanitize all inputs
	req.Username = validation.SanitizeString(req.Username)
	req.Email = validation.SanitizeString(req.Email)
	req.FullName = validation.SanitizeString(req.FullName)
	req.Password = validation.SanitizeString(req.Password)
	
	// Validate username
	if err := validation.Username(req.Username); err != nil {
		return validation.ValidationError("username", err.Error())
	}

	// Validate email
	if err := validation.ValidateEmail(req.Email); err != nil {
		return validation.ValidationError("email", err.Error())
	}

	// Validate full name
	if req.FullName == "" {
		return validation.ValidationError("full_name", "Full name is required")
	}
	if len(req.FullName) < 2 || len(req.FullName) > 100 {
		return validation.ValidationError("full_name", "Full name must be between 2 and 100 characters")
	}

	// Validate password
	if err := validation.Password(req.Password); err != nil {
		return validation.ValidationError("password", err.Error())
	}

	return nil
}