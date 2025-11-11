package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"authservice/internal/service"
)

// SecurityHandler handles security-related endpoints
type SecurityHandler struct {
	authService     *service.AuthService
	securityService *service.SecurityService
}

// NewSecurityHandler creates a new security handler
func NewSecurityHandler(authService *service.AuthService, securityService *service.SecurityService) *SecurityHandler {
	return &SecurityHandler{
		authService:     authService,
		securityService: securityService,
	}
}

// ValidatePasswordRequest represents a password validation request
type ValidatePasswordRequest struct {
	Password string `json:"password"`
}

// ValidatePassword validates password strength
func (h *SecurityHandler) ValidatePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ValidatePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required", "")
		return
	}

	strength := h.securityService.ValidatePasswordStrength(req.Password)
	respondWithJSON(w, http.StatusOK, strength)
}

// RevokeTokenRequest represents a token revocation request
type RevokeTokenRequest struct {
	Token string `json:"token"`
}

// RevokeToken revokes/blacklists a token
func (h *SecurityHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}

	var req RevokeTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Token == "" {
		respondWithError(w, http.StatusBadRequest, "Token is required", "")
		return
	}

	err := h.authService.RevokeToken(req.Token)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to revoke token", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Token revoked successfully",
	})
}

// RevokeCurrentToken revokes the current access token
func (h *SecurityHandler) RevokeCurrentToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}

	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondWithError(w, http.StatusBadRequest, "Authorization header required", "")
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		respondWithError(w, http.StatusBadRequest, "Invalid authorization header format", "")
		return
	}

	token := parts[1]
	err := h.authService.RevokeToken(token)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to revoke token", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Token revoked successfully",
	})
}

// GetSecurityStatusRequest represents a security status request
type GetSecurityStatusRequest struct {
	Email string `json:"email"`
}

// GetSecurityStatus gets security status for an email
func (h *SecurityHandler) GetSecurityStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userID := r.Context().Value("user_id")
	if userID == nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized", "")
		return
	}

	var email string
	if r.Method == http.MethodPost {
		var req GetSecurityStatusRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
			return
		}
		email = req.Email
	} else {
		email = r.URL.Query().Get("email")
	}

	if email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required", "")
		return
	}

	status := h.securityService.GetSecurityStatus(email)
	respondWithJSON(w, http.StatusOK, status)
}

// CheckSuspiciousActivityRequest represents a suspicious activity check request
type CheckSuspiciousActivityRequest struct {
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	DeviceType string `json:"device_type"`
}

// CheckSuspiciousActivity checks for suspicious login patterns
func (h *SecurityHandler) CheckSuspiciousActivity(w http.ResponseWriter, r *http.Request) {
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

	var req CheckSuspiciousActivityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Extract from request if not provided
	if req.IPAddress == "" {
		req.IPAddress = getClientIP(r)
	}
	if req.UserAgent == "" {
		req.UserAgent = r.Header.Get("User-Agent")
	}
	if req.DeviceType == "" {
		req.DeviceType = detectDeviceType(req.UserAgent)
	}

	activity := h.securityService.DetectSuspiciousActivity(
		userIDInt,
		req.IPAddress,
		req.UserAgent,
		req.DeviceType,
	)

	respondWithJSON(w, http.StatusOK, activity)
}

