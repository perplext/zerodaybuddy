package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenManager handles JWT token creation and validation
type TokenManager struct {
	secret         []byte
	issuer         string
	accessExpiry   time.Duration
	refreshExpiry  time.Duration
}

// NewTokenManager creates a new token manager
func NewTokenManager(secret, issuer string) *TokenManager {
	return &TokenManager{
		secret:         []byte(secret),
		issuer:         issuer,
		accessExpiry:   15 * time.Minute,   // Access tokens expire in 15 minutes
		refreshExpiry:  7 * 24 * time.Hour, // Refresh tokens expire in 7 days
	}
}

// Claims represents JWT claims
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Role     UserRole `json:"role"`
	Type     string   `json:"type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// TokenPair represents an access/refresh token pair
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// GenerateTokenPair generates both access and refresh tokens
func (tm *TokenManager) GenerateTokenPair(user *User) (*TokenPair, error) {
	now := time.Now()

	// Generate access token
	accessClaims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Type:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tm.accessExpiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(tm.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := &Claims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Type:     "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tm.refreshExpiry)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(tm.secret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		ExpiresIn:    int64(tm.accessExpiry.Seconds()),
	}, nil
}

// ValidateToken validates and parses a JWT token
func (tm *TokenManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// RefreshTokens generates new tokens using a refresh token
func (tm *TokenManager) RefreshTokens(refreshToken string, user *User) (*TokenPair, error) {
	// Validate the refresh token
	claims, err := tm.ValidateToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	// Ensure it's a refresh token
	if claims.Type != "refresh" {
		return nil, fmt.Errorf("token is not a refresh token")
	}

	// Ensure the token belongs to the user
	if claims.UserID != user.ID {
		return nil, fmt.Errorf("token does not belong to user")
	}

	// Generate new token pair
	return tm.GenerateTokenPair(user)
}

// GenerateSessionToken generates a random session token
func GenerateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate session token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateCSRFToken generates a random CSRF token
func GenerateCSRFToken() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}