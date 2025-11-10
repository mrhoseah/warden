package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"authservice/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles core authentication business logic
type AuthService struct {
	userStore    *models.UserStore
	jwtSecret    []byte
	emailService EmailService
}

// TokenPair represents an access and refresh token pair
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Claims represents JWT claims
type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Type   string `json:"type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// NewAuthService creates a new authentication service
func NewAuthService(userStore *models.UserStore, emailService EmailService) *AuthService {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "your-secret-key-change-in-production" // Default for development
	}

	return &AuthService{
		userStore:    userStore,
		jwtSecret:    []byte(secret),
		emailService: emailService,
	}
}

// Register creates a new user and returns a token pair
func (s *AuthService) Register(email, password string) (*TokenPair, error) {
	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	// Create user
	user, err := s.userStore.CreateUser(email, string(hashedPassword))
	if err != nil {
		return nil, err
	}

	// Send verification email
	verificationToken, err := s.generateVerificationToken(user.ID, user.Email)
	if err == nil {
		s.emailService.SendVerificationEmail(user.Email, verificationToken)
	}

	// Generate token pair
	return s.generateTokenPair(user)
}

// LoginResponse represents the response from login (may require 2FA)
type LoginResponse struct {
	RequiresTwoFactor bool       `json:"requires_two_factor,omitempty"`
	TokenPair         *TokenPair `json:"token_pair,omitempty"`
}

// Login authenticates a user and returns a token pair or indicates 2FA is required
func (s *AuthService) Login(email, password string) (*LoginResponse, error) {
	// Get user by email
	user, err := s.userStore.GetUserByEmail(email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// If 2FA is enabled, return indication that 2FA code is required
	if user.TwoFactorEnabled {
		return &LoginResponse{
			RequiresTwoFactor: true,
		}, nil
	}

	// Generate token pair
	tokenPair, err := s.generateTokenPair(user)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		RequiresTwoFactor: false,
		TokenPair:         tokenPair,
	}, nil
}

// LoginWithTwoFactor authenticates a user with password and 2FA code
func (s *AuthService) LoginWithTwoFactor(email, password, twoFactorCode string) (*TokenPair, error) {
	// Get user by email
	user, err := s.userStore.GetUserByEmail(email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("invalid credentials")
	}

	// Verify 2FA is enabled
	if !user.TwoFactorEnabled {
		return nil, errors.New("two-factor authentication is not enabled")
	}

	// Verify 2FA code
	valid, err := s.VerifyTwoFactorCode(user, twoFactorCode)
	if err != nil || !valid {
		return nil, errors.New("invalid two-factor authentication code")
	}

	// Generate token pair
	return s.generateTokenPair(user)
}

// RefreshToken exchanges a refresh token for a new token pair
func (s *AuthService) RefreshToken(refreshTokenString string) (*TokenPair, error) {
	// Parse and validate refresh token
	token, err := jwt.ParseWithClaims(refreshTokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || claims.Type != "refresh" {
		return nil, errors.New("invalid refresh token")
	}

	// Get user
	user, err := s.userStore.GetUserByID(claims.UserID)
	if err != nil {
		return nil, errors.New("user not found")
	}

	// Generate new token pair
	return s.generateTokenPair(user)
}

// ValidateAccessToken validates an access token and returns the user ID
func (s *AuthService) ValidateAccessToken(accessTokenString string) (int, error) {
	// Parse and validate access token
	token, err := jwt.ParseWithClaims(accessTokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return 0, errors.New("invalid access token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || claims.Type != "access" {
		return 0, errors.New("invalid access token")
	}

	return claims.UserID, nil
}

// generateTokenPair creates both access and refresh tokens for a user
func (s *AuthService) generateTokenPair(user *models.User) (*TokenPair, error) {
	now := time.Now()
	accessExpiresAt := now.Add(15 * time.Minute)  // 15 minutes
	refreshExpiresAt := now.Add(7 * 24 * time.Hour) // 7 days

	// Create access token
	accessClaims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(s.jwtSecret)
	if err != nil {
		return nil, err
	}

	// Create refresh token
	refreshClaims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(refreshExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(s.jwtSecret)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    900, // 15 minutes in seconds
	}, nil
}

// RequestPasswordReset generates a password reset token and sends an email
func (s *AuthService) RequestPasswordReset(email string) error {
	user, err := s.userStore.GetUserByEmail(email)
	if err != nil {
		// Don't reveal if user exists or not (security best practice)
		return nil
	}

	// Generate reset token
	token, err := s.generateSecureToken()
	if err != nil {
		return err
	}

	// Store reset token with expiration (1 hour)
	expiresAt := time.Now().Add(1 * time.Hour)
	user.PasswordResetToken = token
	user.PasswordResetExpires = &expiresAt

	if err := s.userStore.UpdateUser(user); err != nil {
		return err
	}

	// Send password reset email
	return s.emailService.SendPasswordResetEmail(user.Email, token)
}

// ResetPassword resets a user's password using a reset token
func (s *AuthService) ResetPassword(token, newPassword string) error {
	// Find user by reset token
	user, err := s.findUserByResetToken(token)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	// Check if token is expired
	if user.PasswordResetExpires == nil || time.Now().After(*user.PasswordResetExpires) {
		return errors.New("reset token has expired")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	// Update password and clear reset token
	user.PasswordHash = string(hashedPassword)
	user.PasswordResetToken = ""
	user.PasswordResetExpires = nil

	return s.userStore.UpdateUser(user)
}

// VerifyEmail verifies a user's email address using a verification token
func (s *AuthService) VerifyEmail(token string) error {
	// Parse and validate verification token
	jwtToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})

	if err != nil || !jwtToken.Valid {
		return errors.New("invalid verification token")
	}

	claims, ok := jwtToken.Claims.(*Claims)
	if !ok || claims.Type != "verification" {
		return errors.New("invalid verification token")
	}

	// Get user
	user, err := s.userStore.GetUserByID(claims.UserID)
	if err != nil {
		return errors.New("user not found")
	}

	// Check if already verified
	if user.EmailVerified {
		return models.ErrEmailAlreadyVerified
	}

	// Mark email as verified
	now := time.Now()
	user.EmailVerified = true
	user.EmailVerifiedAt = &now

	return s.userStore.UpdateUser(user)
}

// ResendVerificationEmail sends a new verification email to the user
func (s *AuthService) ResendVerificationEmail(email string) error {
	user, err := s.userStore.GetUserByEmail(email)
	if err != nil {
		return err
	}

	if user.EmailVerified {
		return models.ErrEmailAlreadyVerified
	}

	verificationToken, err := s.generateVerificationToken(user.ID, user.Email)
	if err != nil {
		return err
	}

	return s.emailService.SendVerificationEmail(user.Email, verificationToken)
}

// generateVerificationToken creates a JWT token for email verification
func (s *AuthService) generateVerificationToken(userID int, email string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour) // 24 hours to verify

	claims := &Claims{
		UserID: userID,
		Email:  email,
		Type:   "verification",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// generateSecureToken generates a cryptographically secure random token
func (s *AuthService) generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// findUserByResetToken finds a user by their password reset token
func (s *AuthService) findUserByResetToken(token string) (*models.User, error) {
	return s.userStore.GetUserByResetToken(token)
}

// OAuthProvider represents an OAuth provider
type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
	OAuthProviderGitHub OAuthProvider = "github"
)

// OAuthUserInfo contains user information from OAuth provider
type OAuthUserInfo struct {
	ProviderID string
	Email      string
	Name       string
	Provider   OAuthProvider
}

// AuthenticateWithOAuth authenticates or creates a user via OAuth
func (s *AuthService) AuthenticateWithOAuth(oauthInfo OAuthUserInfo) (*TokenPair, error) {
	// Try to find existing user by email
	user, err := s.userStore.GetUserByEmail(oauthInfo.Email)
	
	if err != nil {
		// User doesn't exist, create new user
		// For OAuth users, we generate a random password (they won't use it)
		randomPassword, _ := s.generateSecureToken()
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(randomPassword), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}

		user, err = s.userStore.CreateUser(oauthInfo.Email, string(hashedPassword))
		if err != nil {
			return nil, err
		}

		// OAuth users are automatically verified
		now := time.Now()
		user.EmailVerified = true
		user.EmailVerifiedAt = &now
		if err := s.userStore.UpdateUser(user); err != nil {
			return nil, err
		}
	} else {
		// User exists, mark as verified if not already
		if !user.EmailVerified {
			now := time.Now()
			user.EmailVerified = true
			user.EmailVerifiedAt = &now
			if err := s.userStore.UpdateUser(user); err != nil {
				return nil, err
			}
		}
	}

	// Generate token pair
	return s.generateTokenPair(user)
}

// EnableTwoFactor generates a TOTP secret and QR code for 2FA setup
func (s *AuthService) EnableTwoFactor(userID int) (string, string, []string, error) {
	user, err := s.userStore.GetUserByID(userID)
	if err != nil {
		return "", "", nil, err
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "AuthService", // Change this to your app name
		AccountName: user.Email,
	})
	if err != nil {
		return "", "", nil, err
	}

	// Generate backup codes
	backupCodes := s.generateBackupCodes(8)

	// Store secret and backup codes (but don't enable yet - user must verify first)
	user.TOTPSecret = key.Secret()
	user.BackupCodes = backupCodes

	if err := s.userStore.UpdateUser(user); err != nil {
		return "", "", nil, err
	}

	return key.Secret(), key.URL(), backupCodes, nil
}

// VerifyTwoFactorSetup verifies the 2FA code and enables 2FA for the user
func (s *AuthService) VerifyTwoFactorSetup(userID int, code string) ([]string, error) {
	user, err := s.userStore.GetUserByID(userID)
	if err != nil {
		return nil, err
	}

	if user.TOTPSecret == "" {
		return nil, errors.New("two-factor authentication not initialized")
	}

	// Verify the code
	valid := totp.Validate(code, user.TOTPSecret)
	if !valid {
		return nil, errors.New("invalid verification code")
	}

	// Enable 2FA
	user.TwoFactorEnabled = true
	if err := s.userStore.UpdateUser(user); err != nil {
		return nil, err
	}

	// Return backup codes
	return user.BackupCodes, nil
}

// VerifyTwoFactorCode verifies a 2FA code or backup code
func (s *AuthService) VerifyTwoFactorCode(user *models.User, code string) (bool, error) {
	if !user.TwoFactorEnabled || user.TOTPSecret == "" {
		return false, errors.New("two-factor authentication not enabled")
	}

	// First, try TOTP code
	valid := totp.Validate(code, user.TOTPSecret)
	if valid {
		return true, nil
	}

	// If TOTP fails, check backup codes
	for i, backupCode := range user.BackupCodes {
		if backupCode == code {
			// Remove used backup code
			user.BackupCodes = append(user.BackupCodes[:i], user.BackupCodes[i+1:]...)
			if err := s.userStore.UpdateUser(user); err != nil {
				return false, err
			}
			return true, nil
		}
	}

	return false, nil
}

// DisableTwoFactor disables 2FA for a user
func (s *AuthService) DisableTwoFactor(userID int) error {
	user, err := s.userStore.GetUserByID(userID)
	if err != nil {
		return err
	}

	user.TwoFactorEnabled = false
	user.TOTPSecret = ""
	user.BackupCodes = nil

	return s.userStore.UpdateUser(user)
}

// GetTwoFactorQRCode returns the QR code URL for a user's 2FA setup
func (s *AuthService) GetTwoFactorQRCode(userID int) (string, error) {
	user, err := s.userStore.GetUserByID(userID)
	if err != nil {
		return "", err
	}

	if user.TOTPSecret == "" {
		return "", errors.New("two-factor authentication not initialized")
	}

	key, err := otp.NewKeyFromURL("otpauth://totp/AuthService:" + user.Email + "?secret=" + user.TOTPSecret + "&issuer=AuthService")
	if err != nil {
		return "", err
	}

	return key.URL(), nil
}

// generateBackupCodes generates cryptographically secure backup codes
func (s *AuthService) generateBackupCodes(count int) []string {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		bytes := make([]byte, 4) // 8 hex characters
		rand.Read(bytes)
		codes[i] = hex.EncodeToString(bytes)
	}
	return codes
}

