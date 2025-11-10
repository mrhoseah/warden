package handler

import (
	"encoding/json"
	"net/http"

	"authservice/internal/service"
)

// Handler handles HTTP requests for authentication
type Handler struct {
	authService *service.AuthService
}

// NewHandler creates a new HTTP handler
func NewHandler(authService *service.AuthService) *Handler {
	return &Handler{
		authService: authService,
	}
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest represents a refresh token request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// Register godoc
// @Summary      Register a new user
// @Description  Creates a new user account and returns access/refresh tokens
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        request  body      RegisterRequest  true  "Registration request"
// @Success      201      {object}  service.TokenPair
// @Failure      400      {object}  ErrorResponse
// @Failure      409      {object}  ErrorResponse
// @Router       /register [post]
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Email and password are required", "")
		return
	}

	// Register user
	tokenPair, err := h.authService.Register(req.Email, req.Password)
	if err != nil {
		statusCode := http.StatusInternalServerError
		if err.Error() == "user already exists" {
			statusCode = http.StatusConflict
		}
		respondWithError(w, statusCode, "Registration failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusCreated, tokenPair)
}

// Login godoc
// @Summary      Login with email and password
// @Description  Authenticates a user and returns tokens. If 2FA is enabled, returns requires_two_factor flag.
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        request  body      LoginRequest  true  "Login request"
// @Success      200      {object}  service.LoginResponse
// @Failure      400      {object}  ErrorResponse
// @Failure      401      {object}  ErrorResponse
// @Router       /login [post]
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Email and password are required", "")
		return
	}

	// Authenticate user
	loginResponse, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, loginResponse)
}

// LoginWithTwoFactorRequest represents a login with 2FA request
type LoginWithTwoFactorRequest struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	TwoFactorCode string `json:"two_factor_code"`
}

// LoginWithTwoFactor godoc
// @Summary      Login with 2FA code
// @Description  Completes login when 2FA is enabled by providing the TOTP code
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        request  body      LoginWithTwoFactorRequest  true  "Login with 2FA request"
// @Success      200      {object}  service.TokenPair
// @Failure      400      {object}  ErrorResponse
// @Failure      401      {object}  ErrorResponse
// @Router       /login/2fa [post]
func (h *Handler) LoginWithTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginWithTwoFactorRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" || req.TwoFactorCode == "" {
		respondWithError(w, http.StatusBadRequest, "Email, password, and two-factor code are required", "")
		return
	}

	// Authenticate with 2FA
	tokenPair, err := h.authService.LoginWithTwoFactor(req.Email, req.Password, req.TwoFactorCode)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, tokenPair)
}

// Refresh godoc
// @Summary      Refresh access token
// @Description  Exchanges a refresh token for a new access/refresh token pair
// @Tags         authentication
// @Accept       json
// @Produce      json
// @Param        request  body      RefreshRequest  true  "Refresh token request"
// @Success      200      {object}  service.TokenPair
// @Failure      400      {object}  ErrorResponse
// @Failure      401      {object}  ErrorResponse
// @Router       /refresh [post]
func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate input
	if req.RefreshToken == "" {
		respondWithError(w, http.StatusBadRequest, "Refresh token is required", "")
		return
	}

	// Refresh token
	tokenPair, err := h.authService.RefreshToken(req.RefreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Token refresh failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, tokenPair)
}

// User godoc
// @Summary      Get authenticated user
// @Description  Returns information about the currently authenticated user
// @Tags         user
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]interface{}
// @Failure      401  {object}  ErrorResponse
// @Router       /user [get]
func (h *Handler) User(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// User ID is set by middleware
	userID := r.Context().Value("user_id")
	if userID == nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"message": "User is authenticated and details would be here.",
		"status":  "ok",
		"user_id": userID,
	})
}

// respondWithJSON sends a JSON response
func respondWithJSON(w http.ResponseWriter, statusCode int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(payload)
}

// respondWithError sends an error JSON response
func respondWithError(w http.ResponseWriter, statusCode int, error, message string) {
	response := ErrorResponse{
		Error: error,
	}
	if message != "" {
		response.Message = message
	}
	respondWithJSON(w, statusCode, response)
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	Email string `json:"email"`
}

// PasswordResetConfirmRequest represents a password reset confirmation
type PasswordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

// RequestPasswordReset godoc
// @Summary      Request password reset
// @Description  Sends a password reset email to the user
// @Tags         password
// @Accept       json
// @Produce      json
// @Param        request  body      PasswordResetRequest  true  "Password reset request"
// @Success      200      {object}  map[string]string
// @Failure      400      {object}  ErrorResponse
// @Router       /password/reset [post]
func (h *Handler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required", "")
		return
	}

	// Request password reset (always returns success for security)
	err := h.authService.RequestPasswordReset(req.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to process request", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "If an account with that email exists, a password reset link has been sent.",
	})
}

// ResetPassword godoc
// @Summary      Confirm password reset
// @Description  Resets the password using a token from the reset email
// @Tags         password
// @Accept       json
// @Produce      json
// @Param        request  body      PasswordResetConfirmRequest  true  "Password reset confirmation"
// @Success      200      {object}  map[string]string
// @Failure      400      {object}  ErrorResponse
// @Router       /password/reset/confirm [post]
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req PasswordResetConfirmRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		respondWithError(w, http.StatusBadRequest, "Token and new password are required", "")
		return
	}

	err := h.authService.ResetPassword(req.Token, req.NewPassword)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Password reset failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Password has been reset successfully",
	})
}

// VerifyEmailRequest represents an email verification request
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmail godoc
// @Summary      Verify email address
// @Description  Verifies a user's email address using a token from the verification email
// @Tags         email
// @Accept       json
// @Produce      json
// @Param        request  body      VerifyEmailRequest  true  "Email verification request"
// @Success      200      {object}  map[string]string
// @Failure      400      {object}  ErrorResponse
// @Router       /email/verify [post]
func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Token == "" {
		respondWithError(w, http.StatusBadRequest, "Token is required", "")
		return
	}

	err := h.authService.VerifyEmail(req.Token)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Email verification failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Email verified successfully",
	})
}

// ResendVerificationRequest represents a resend verification request
type ResendVerificationRequest struct {
	Email string `json:"email"`
}

// ResendVerificationEmail handles resending verification email
func (h *Handler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ResendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required", "")
		return
	}

	err := h.authService.ResendVerificationEmail(req.Email)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to resend verification email", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Verification email sent",
	})
}

// EnableTwoFactorRequest represents a 2FA enable request
type EnableTwoFactorRequest struct {
	Code string `json:"code,omitempty"` // Optional, for verification step
}

// EnableTwoFactor godoc
// @Summary      Enable two-factor authentication
// @Description  Generates a QR code for 2FA setup. Send code in body to verify and activate.
// @Tags         two-factor
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      EnableTwoFactorRequest  false  "2FA enable request (optional code for verification)"
// @Success      200      {object}  map[string]interface{}
// @Failure      400      {object}  ErrorResponse
// @Failure      401      {object}  ErrorResponse
// @Router       /2fa/enable [post]
func (h *Handler) EnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}

	userIDInt, ok := userID.(int)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Invalid user ID", "")
		return
	}

	// Check if code is provided (verification step)
	var req EnableTwoFactorRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.Code != "" {
		// Verify and enable 2FA
		backupCodes, err := h.authService.VerifyTwoFactorSetup(userIDInt, req.Code)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "Verification failed", err.Error())
			return
		}

		respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"message":      "Two-factor authentication enabled successfully",
			"backup_codes": backupCodes,
		})
		return
	}

	// Generate new 2FA setup
	secret, qrURL, backupCodes, err := h.authService.EnableTwoFactor(userIDInt)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to enable 2FA", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"secret":       secret,
		"qr_code_url":  qrURL,
		"backup_codes": backupCodes,
		"message":      "Scan the QR code with your authenticator app and verify with a code",
	})
}

// DisableTwoFactor godoc
// @Summary      Disable two-factor authentication
// @Description  Disables 2FA for the authenticated user
// @Tags         two-factor
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string]string
// @Failure      401  {object}  ErrorResponse
// @Router       /2fa/disable [post]
func (h *Handler) DisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}

	userIDInt, ok := userID.(int)
	if !ok {
		respondWithError(w, http.StatusInternalServerError, "Invalid user ID", "")
		return
	}

	err := h.authService.DisableTwoFactor(userIDInt)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to disable 2FA", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Two-factor authentication disabled successfully",
	})
}

// OAuthCallbackRequest represents an OAuth callback request
type OAuthCallbackRequest struct {
	Provider   string `json:"provider"`
	ProviderID string `json:"provider_id"`
	Email      string `json:"email"`
	Name       string `json:"name"`
}

// OAuthCallback handles OAuth authentication
func (h *Handler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req OAuthCallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Provider == "" || req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Provider and email are required", "")
		return
	}

	oauthInfo := service.OAuthUserInfo{
		ProviderID: req.ProviderID,
		Email:      req.Email,
		Name:       req.Name,
		Provider:   service.OAuthProvider(req.Provider),
	}

	tokenPair, err := h.authService.AuthenticateWithOAuth(oauthInfo)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "OAuth authentication failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, tokenPair)
}

