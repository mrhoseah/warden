package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"authservice/internal/service"
)

// ModernAuthHandler handles modern authentication features
type ModernAuthHandler struct {
	modernAuthService *service.ModernAuthService
}

// NewModernAuthHandler creates a new modern auth handler
func NewModernAuthHandler(modernAuthService *service.ModernAuthService) *ModernAuthHandler {
	return &ModernAuthHandler{
		modernAuthService: modernAuthService,
	}
}

// RequestMagicLinkRequest represents a magic link request
type RequestMagicLinkRequest struct {
	Email string `json:"email"`
}

// RequestMagicLink handles magic link request
func (h *ModernAuthHandler) RequestMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RequestMagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Email == "" {
		respondWithError(w, http.StatusBadRequest, "Email is required", "")
		return
	}

	err := h.modernAuthService.RequestMagicLink(req.Email)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to send magic link", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "If an account with that email exists, a magic link has been sent.",
	})
}

// LoginWithMagicLinkRequest represents a magic link login request
type LoginWithMagicLinkRequest struct {
	Token string `json:"token"`
}

// LoginWithMagicLink handles magic link authentication
func (h *ModernAuthHandler) LoginWithMagicLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginWithMagicLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Token == "" {
		respondWithError(w, http.StatusBadRequest, "Token is required", "")
		return
	}

	deviceInfo := extractDeviceInfo(r)
	tokenPair, session, err := h.modernAuthService.LoginWithMagicLink(req.Token, deviceInfo)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Authentication failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"token_type":    tokenPair.TokenType,
		"expires_in":    tokenPair.ExpiresIn,
		"session_id":    session.ID,
	})
}

// GetSessions handles getting user sessions
func (h *ModernAuthHandler) GetSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	sessions := h.modernAuthService.GetUserSessions(userIDInt)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"sessions": sessions,
	})
}

// RevokeSessionRequest represents a session revocation request
type RevokeSessionRequest struct {
	SessionID string `json:"session_id"`
}

// RevokeSession handles session revocation
func (h *ModernAuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
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

	var req RevokeSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	err := h.modernAuthService.RevokeSession(userIDInt, req.SessionID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to revoke session", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Session revoked successfully",
	})
}

// RevokeAllSessions handles revoking all user sessions
func (h *ModernAuthHandler) RevokeAllSessions(w http.ResponseWriter, r *http.Request) {
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

	err := h.modernAuthService.RevokeAllSessions(userIDInt)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to revoke sessions", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "All sessions revoked successfully",
	})
}

// MarkDeviceAsTrustedRequest represents a trusted device request
type MarkDeviceAsTrustedRequest struct {
	SessionID string `json:"session_id"`
}

// MarkDeviceAsTrusted handles marking a device as trusted
func (h *ModernAuthHandler) MarkDeviceAsTrusted(w http.ResponseWriter, r *http.Request) {
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

	var req MarkDeviceAsTrustedRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	err := h.modernAuthService.MarkDeviceAsTrusted(userIDInt, req.SessionID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to mark device as trusted", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Device marked as trusted",
	})
}

// GetLoginHistory handles getting login history
func (h *ModernAuthHandler) GetLoginHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	// Get limit from query parameter (default 50)
	limit := 50
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsedLimit, err := parseInt(limitStr); err == nil {
			limit = parsedLimit
		}
	}

	history := h.modernAuthService.GetLoginHistory(userIDInt, limit)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"history": history,
	})
}

// UpdateProfileRequest represents a profile update request
type UpdateProfileRequest struct {
	Name string `json:"name"`
}

// UpdateProfile handles profile updates
func (h *ModernAuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
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

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	err := h.modernAuthService.UpdateProfile(userIDInt, req.Name)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to update profile", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Profile updated successfully",
	})
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// ChangePassword handles password changes
func (h *ModernAuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
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

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.CurrentPassword == "" || req.NewPassword == "" {
		respondWithError(w, http.StatusBadRequest, "Current password and new password are required", "")
		return
	}

	err := h.modernAuthService.ChangePassword(userIDInt, req.CurrentPassword, req.NewPassword)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to change password", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Password changed successfully",
	})
}

// RequestEmailChangeRequest represents an email change request
type RequestEmailChangeRequest struct {
	NewEmail string `json:"new_email"`
}

// RequestEmailChange handles email change requests
func (h *ModernAuthHandler) RequestEmailChange(w http.ResponseWriter, r *http.Request) {
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

	var req RequestEmailChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.NewEmail == "" {
		respondWithError(w, http.StatusBadRequest, "New email is required", "")
		return
	}

	err := h.modernAuthService.RequestEmailChange(userIDInt, req.NewEmail)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to request email change", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Email change confirmation sent to new email address",
	})
}

// ConfirmEmailChangeRequest represents an email change confirmation
type ConfirmEmailChangeRequest struct {
	Token string `json:"token"`
}

// ConfirmEmailChange handles email change confirmation
func (h *ModernAuthHandler) ConfirmEmailChange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ConfirmEmailChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Token == "" {
		respondWithError(w, http.StatusBadRequest, "Token is required", "")
		return
	}

	err := h.modernAuthService.ConfirmEmailChange(req.Token)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Email change failed", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Email changed successfully",
	})
}

// DeleteAccountRequest represents an account deletion request
type DeleteAccountRequest struct {
	Password string `json:"password"`
}

// DeleteAccount handles account deletion
func (h *ModernAuthHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
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

	var req DeleteAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required", "")
		return
	}

	err := h.modernAuthService.DeleteAccount(userIDInt, req.Password)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to delete account", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "Account deleted successfully",
	})
}

// GenerateAPIKeyRequest represents an API key generation request
type GenerateAPIKeyRequest struct {
	Name         string `json:"name"`
	ExpiresInDays *int  `json:"expires_in_days,omitempty"`
}

// GenerateAPIKey handles API key generation
func (h *ModernAuthHandler) GenerateAPIKey(w http.ResponseWriter, r *http.Request) {
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

	var req GenerateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Name == "" {
		respondWithError(w, http.StatusBadRequest, "Name is required", "")
		return
	}

	apiKey, storedKey, err := h.modernAuthService.GenerateAPIKey(userIDInt, req.Name, req.ExpiresInDays)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to generate API key", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"api_key": apiKey, // Only shown once!
		"key_info": map[string]interface{}{
			"id":         storedKey.ID,
			"name":       storedKey.Name,
			"prefix":     storedKey.Prefix,
			"created_at": storedKey.CreatedAt,
			"expires_at": storedKey.ExpiresAt,
		},
		"message": "API key generated. Store it securely - it won't be shown again!",
	})
}

// GetAPIKeys handles getting user API keys
func (h *ModernAuthHandler) GetAPIKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	keys := h.modernAuthService.GetUserAPIKeys(userIDInt)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"api_keys": keys,
	})
}

// RevokeAPIKeyRequest represents an API key revocation request
type RevokeAPIKeyRequest struct {
	KeyID int `json:"key_id"`
}

// RevokeAPIKey handles API key revocation
func (h *ModernAuthHandler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
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

	var req RevokeAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	err := h.modernAuthService.RevokeAPIKey(userIDInt, req.KeyID)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Failed to revoke API key", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{
		"message": "API key revoked successfully",
	})
}

// Helper functions

func extractDeviceInfo(r *http.Request) service.DeviceInfo {
	userAgent := r.Header.Get("User-Agent")
	ipAddress := getClientIP(r)
	deviceType := detectDeviceType(userAgent)
	deviceName := r.Header.Get("X-Device-Name")
	if deviceName == "" {
		deviceName = "Unknown Device"
	}

	return service.DeviceInfo{
		DeviceName: deviceName,
		DeviceType: deviceType,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
	}
}

func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

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

func parseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

