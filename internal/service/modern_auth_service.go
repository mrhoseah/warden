package service

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"authservice/internal/models"

	"golang.org/x/crypto/bcrypt"
)

// ModernAuthService extends AuthService with modern authentication features
type ModernAuthService struct {
	authService     *AuthService
	sessionStore    *models.SessionStore
	loginHistory    *models.LoginHistoryStore
	apiKeyStore     *models.APIKeyStore
	userStore       *models.UserStore
}

// NewModernAuthService creates a new modern auth service
func NewModernAuthService(authService *AuthService, sessionStore *models.SessionStore, loginHistory *models.LoginHistoryStore, apiKeyStore *models.APIKeyStore, userStore *models.UserStore) *ModernAuthService {
	return &ModernAuthService{
		authService:  authService,
		sessionStore: sessionStore,
		loginHistory: loginHistory,
		apiKeyStore:  apiKeyStore,
		userStore:    userStore,
	}
}

// DeviceInfo represents device information from request
type DeviceInfo struct {
	DeviceName string
	DeviceType string
	IPAddress  string
	UserAgent  string
}

// detectDeviceType detects device type from user agent
func detectDeviceType(userAgent string) string {
	ua := strings.ToLower(userAgent)
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") {
		return "mobile"
	}
	if strings.Contains(ua, "tablet") || strings.Contains(ua, "ipad") {
		return "tablet"
	}
	if strings.Contains(ua, "desktop") || strings.Contains(ua, "windows") || strings.Contains(ua, "mac") || strings.Contains(ua, "linux") {
		return "desktop"
	}
	return "unknown"
}

// LoginWithSession creates a login with session tracking
func (s *ModernAuthService) LoginWithSession(email, password string, deviceInfo DeviceInfo) (*LoginResponse, *models.Session, error) {
	loginResp, err := s.authService.Login(email, password)
	if err != nil {
		s.loginHistory.AddEvent(0, email, deviceInfo.IPAddress, deviceInfo.UserAgent, deviceInfo.DeviceType, false, err.Error(), "password")
		return nil, nil, err
	}

	// Get user for session creation
	user, err := s.userStore.GetUserByEmail(email)
	if err != nil {
		return nil, nil, err
	}

	// Log successful login
	s.loginHistory.AddEvent(user.ID, email, deviceInfo.IPAddress, deviceInfo.UserAgent, deviceInfo.DeviceType, true, "", "password")

	// If 2FA required, don't create session yet
	if loginResp.RequiresTwoFactor {
		return loginResp, nil, nil
	}

	// Create session
	session := s.sessionStore.CreateSession(user.ID, deviceInfo.DeviceName, deviceInfo.DeviceType, deviceInfo.IPAddress, deviceInfo.UserAgent, false)

	return loginResp, session, nil
}

// LoginWithMagicLink authenticates using a magic link token
func (s *ModernAuthService) LoginWithMagicLink(token string, deviceInfo DeviceInfo) (*TokenPair, *models.Session, error) {
	user, err := s.userStore.GetUserByMagicLinkToken(token)
	if err != nil {
		s.loginHistory.AddEvent(0, "", deviceInfo.IPAddress, deviceInfo.UserAgent, deviceInfo.DeviceType, false, "invalid token", "magic_link")
		return nil, nil, errors.New("invalid or expired magic link")
	}

	// Check expiration
	if user.MagicLinkExpires != nil && time.Now().After(*user.MagicLinkExpires) {
		s.loginHistory.AddEvent(user.ID, user.Email, deviceInfo.IPAddress, deviceInfo.UserAgent, deviceInfo.DeviceType, false, "token expired", "magic_link")
		return nil, nil, errors.New("magic link has expired")
	}

	// Clear magic link token
	user.MagicLinkToken = ""
	user.MagicLinkExpires = nil
	s.userStore.UpdateUser(user)

	// Generate token pair - we need to access it through a helper
	// Since generateTokenPair is private, we'll create tokens directly
	tokenPair, err := s.generateTokenPairForUser(user)
	if err != nil {
		return nil, nil, err
	}

	// Log successful login
	s.loginHistory.AddEvent(user.ID, user.Email, deviceInfo.IPAddress, deviceInfo.UserAgent, deviceInfo.DeviceType, true, "", "magic_link")

	// Create session
	session := s.sessionStore.CreateSession(user.ID, deviceInfo.DeviceName, deviceInfo.DeviceType, deviceInfo.IPAddress, deviceInfo.UserAgent, false)

	return tokenPair, session, nil
}

// RequestMagicLink sends a magic link for passwordless login
func (s *ModernAuthService) RequestMagicLink(email string) error {
	user, err := s.userStore.GetUserByEmail(email)
	if err != nil {
		// Don't reveal if user exists (security)
		return nil
	}

	// Generate magic link token
	token, err := s.generateSecureToken()
	if err != nil {
		return err
	}

	// Store token with expiration (15 minutes)
	expiresAt := time.Now().Add(15 * time.Minute)
	user.MagicLinkToken = token
	user.MagicLinkExpires = &expiresAt

	if err := s.userStore.UpdateUser(user); err != nil {
		return err
	}

	// Send magic link email
	return s.authService.emailService.SendMagicLinkEmail(user.Email, token)
}

// GetUserSessions retrieves all active sessions for a user
func (s *ModernAuthService) GetUserSessions(userID int) []*models.Session {
	return s.sessionStore.GetUserSessions(userID)
}

// RevokeSession revokes a specific session
func (s *ModernAuthService) RevokeSession(userID int, sessionID string) error {
	// Verify session belongs to user
	session, exists := s.sessionStore.GetSession(sessionID)
	if !exists || session.UserID != userID {
		return errors.New("session not found")
	}

	return s.sessionStore.RevokeSession(sessionID)
}

// RevokeAllSessions revokes all sessions for a user
func (s *ModernAuthService) RevokeAllSessions(userID int) error {
	return s.sessionStore.RevokeAllUserSessions(userID)
}

// MarkDeviceAsTrusted marks a device/session as trusted
func (s *ModernAuthService) MarkDeviceAsTrusted(userID int, sessionID string) error {
	session, exists := s.sessionStore.GetSession(sessionID)
	if !exists || session.UserID != userID {
		return errors.New("session not found")
	}

	return s.sessionStore.MarkSessionAsTrusted(sessionID)
}

// GetLoginHistory retrieves login history for a user
func (s *ModernAuthService) GetLoginHistory(userID int, limit int) []*models.LoginEvent {
	return s.loginHistory.GetUserHistory(userID, limit)
}

// UpdateProfile updates user profile information
func (s *ModernAuthService) UpdateProfile(userID int, name string) error {
	user, err := s.userStore.GetUserByID(userID)
	if err != nil {
		return err
	}

	user.Name = name
	user.UpdatedAt = time.Now()

	return s.userStore.UpdateUser(user)
}

// ChangePassword changes user password (requires current password)
func (s *ModernAuthService) ChangePassword(userID int, currentPassword, newPassword string) error {
	user, err := s.userStore.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Verify current password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(currentPassword))
	if err != nil {
		return errors.New("current password is incorrect")
	}

	// Validate password strength (if security service is available)
	securityService := s.authService.GetSecurityService()
	if securityService != nil {
		strength := securityService.ValidatePasswordStrength(newPassword)
		if !strength.Valid {
			return errors.New("password does not meet strength requirements: " + strings.Join(strength.Issues, ", "))
		}
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(hashedPassword)
	user.UpdatedAt = time.Now()

	return s.userStore.UpdateUser(user)
}

// RequestEmailChange requests an email change
func (s *ModernAuthService) RequestEmailChange(userID int, newEmail string) error {
	user, err := s.userStore.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Check if new email is already in use
	_, err = s.userStore.GetUserByEmail(newEmail)
	if err == nil {
		return errors.New("email already in use")
	}

	// Generate email change token
	token, err := s.generateSecureToken()
	if err != nil {
		return err
	}

	// Store token with expiration (24 hours)
	expiresAt := time.Now().Add(24 * time.Hour)
	user.EmailChangeToken = token
	user.EmailChangeNewEmail = newEmail
	user.EmailChangeExpires = &expiresAt

	if err := s.userStore.UpdateUser(user); err != nil {
		return err
	}

	// Send confirmation email
	return s.authService.emailService.SendEmailChangeConfirmationEmail(user.Email, newEmail, token)
}

// ConfirmEmailChange confirms and applies email change
func (s *ModernAuthService) ConfirmEmailChange(token string) error {
	user, err := s.userStore.GetUserByEmailChangeToken(token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	// Check expiration
	if user.EmailChangeExpires != nil && time.Now().After(*user.EmailChangeExpires) {
		return errors.New("email change token has expired")
	}

	// Update email
	user.Email = user.EmailChangeNewEmail
	user.EmailChangeToken = ""
	user.EmailChangeNewEmail = ""
	user.EmailChangeExpires = nil
	user.EmailVerified = false // Require re-verification
	user.UpdatedAt = time.Now()

	// Update in store (need to handle email change in map)
	// For simplicity, we'll update the user object
	// In production with a database, this would be a transaction
	s.userStore.UpdateUser(user)

	// Send verification email to new address
	verificationToken, err := s.authService.generateVerificationToken(user.ID, user.Email)
	if err == nil {
		s.authService.emailService.SendVerificationEmail(user.Email, verificationToken)
	}

	return nil
}

// DeleteAccount deletes a user account
func (s *ModernAuthService) DeleteAccount(userID int, password string) error {
	user, err := s.userStore.GetUserByID(userID)
	if err != nil {
		return err
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return errors.New("password is incorrect")
	}

	// Revoke all sessions
	s.sessionStore.RevokeAllUserSessions(userID)

	// Mark account as inactive (soft delete)
	user.Active = false
	user.UpdatedAt = time.Now()

	return s.userStore.UpdateUser(user)
}

// GenerateAPIKey generates a new API key for service-to-service authentication
func (s *ModernAuthService) GenerateAPIKey(userID int, name string, expiresInDays *int) (string, *models.APIKey, error) {
	// Generate API key (format: prefix_random)
	prefix := "ak_" + randomString(8)
	randomPart := randomString(32)
	apiKey := prefix + "_" + randomPart

	// Hash the key for storage
	keyHash, err := bcrypt.GenerateFromPassword([]byte(apiKey), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	// Set expiration
	var expiresAt *time.Time
	if expiresInDays != nil {
		exp := time.Now().Add(time.Duration(*expiresInDays) * 24 * time.Hour)
		expiresAt = &exp
	}

	// Store API key
	storedKey := s.apiKeyStore.CreateAPIKey(userID, name, string(keyHash), prefix, expiresAt)

	return apiKey, storedKey, nil
}

// ValidateAPIKey validates an API key and returns user ID
func (s *ModernAuthService) ValidateAPIKey(apiKey string) (int, error) {
	// Extract prefix
	parts := strings.Split(apiKey, "_")
	if len(parts) < 3 || parts[0] != "ak" {
		return 0, errors.New("invalid API key format")
	}

	prefix := parts[0] + "_" + parts[1]

	// Get key by prefix
	key, exists := s.apiKeyStore.GetAPIKeyByPrefix(prefix)
	if !exists {
		return 0, errors.New("invalid API key")
	}

	// Verify hash
	err := bcrypt.CompareHashAndPassword([]byte(key.KeyHash), []byte(apiKey))
	if err != nil {
		return 0, errors.New("invalid API key")
	}

	// Update last used
	s.apiKeyStore.UpdateLastUsed(key.KeyHash)

	return key.UserID, nil
}

// GetUserAPIKeys retrieves all API keys for a user
func (s *ModernAuthService) GetUserAPIKeys(userID int) []*models.APIKey {
	return s.apiKeyStore.GetUserAPIKeys(userID)
}

// RevokeAPIKey revokes an API key
func (s *ModernAuthService) RevokeAPIKey(userID int, keyID int) error {
	keys := s.apiKeyStore.GetUserAPIKeys(userID)
	for _, key := range keys {
		if key.ID == keyID && key.UserID == userID {
			return s.apiKeyStore.RevokeAPIKey(key.KeyHash)
		}
	}
	return errors.New("API key not found")
}

// Helper function to generate secure token
func (s *ModernAuthService) generateSecureToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Helper function for random string generation
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

// generateTokenPairForUser generates tokens for a user
func (s *ModernAuthService) generateTokenPairForUser(user *models.User) (*TokenPair, error) {
	return s.authService.GenerateTokenPair(user)
}

// GetAuthService returns the underlying auth service (for token generation)
func (s *ModernAuthService) GetAuthService() *AuthService {
	return s.authService
}

