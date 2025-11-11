package handler

import (
	"encoding/json"
	"net/http"

	"authservice/internal/service"
)

// AdvancedSecurityHandler handles advanced security features
type AdvancedSecurityHandler struct {
	advancedSecurityService *service.AdvancedSecurityService
}

// NewAdvancedSecurityHandler creates a new advanced security handler
func NewAdvancedSecurityHandler(advancedSecurityService *service.AdvancedSecurityService) *AdvancedSecurityHandler {
	return &AdvancedSecurityHandler{
		advancedSecurityService: advancedSecurityService,
	}
}

// CheckPasswordBreachRequest represents a password breach check request
type CheckPasswordBreachRequest struct {
	Password string `json:"password"`
}

// CheckPasswordBreach checks if a password has been in a data breach
func (h *AdvancedSecurityHandler) CheckPasswordBreach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CheckPasswordBreachRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required", "")
		return
	}

	result, err := h.advancedSecurityService.CheckPasswordBreach(req.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to check password breach", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, result)
}

// ValidatePasswordWithBreachRequest represents a password validation with breach check
type ValidatePasswordWithBreachRequest struct {
	Password string `json:"password"`
}

// ValidatePasswordWithBreach validates password strength and checks for breaches
func (h *AdvancedSecurityHandler) ValidatePasswordWithBreach(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ValidatePasswordWithBreachRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Password == "" {
		respondWithError(w, http.StatusBadRequest, "Password is required", "")
		return
	}

	strength, breachResult, err := h.advancedSecurityService.ValidatePasswordWithBreachCheck(req.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to validate password", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"strength":     strength,
		"breach_check": breachResult,
	})
}

// EvaluateAdaptiveAuthRequest represents an adaptive auth evaluation request
type EvaluateAdaptiveAuthRequest struct {
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
}

// EvaluateAdaptiveAuth evaluates risk and determines if additional authentication is required
func (h *AdvancedSecurityHandler) EvaluateAdaptiveAuth(w http.ResponseWriter, r *http.Request) {
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

	var req EvaluateAdaptiveAuthRequest
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

	result := h.advancedSecurityService.EvaluateAdaptiveAuth(
		userIDInt,
		req.IPAddress,
		req.UserAgent,
		req.DeviceType,
	)

	respondWithJSON(w, http.StatusOK, result)
}

// DetectSessionHijackingRequest represents a session hijacking detection request
type DetectSessionHijackingRequest struct {
	IPAddress  string `json:"ip_address,omitempty"`
	UserAgent  string `json:"user_agent,omitempty"`
}

// DetectSessionHijacking detects potential session hijacking
func (h *AdvancedSecurityHandler) DetectSessionHijacking(w http.ResponseWriter, r *http.Request) {
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

	var req DetectSessionHijackingRequest
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

	result := h.advancedSecurityService.DetectSessionHijacking(
		userIDInt,
		req.IPAddress,
		req.UserAgent,
	)

	respondWithJSON(w, http.StatusOK, result)
}

// GetAuditLogRequest represents an audit log request
type GetAuditLogRequest struct {
	Limit int `json:"limit,omitempty"`
}

// GetAuditLog retrieves audit logs for the authenticated user
func (h *AdvancedSecurityHandler) GetAuditLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
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

	limit := 50 // default
	if r.Method == http.MethodGet {
		if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
			if parsedLimit, err := parseInt(limitStr); err == nil {
				limit = parsedLimit
			}
		}
	} else {
		var req GetAuditLogRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Limit > 0 {
			limit = req.Limit
		}
	}

	auditLog := h.advancedSecurityService.GetAuditLog(userIDInt, limit)
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"audit_log": auditLog,
		"count":     len(auditLog),
	})
}

// GetIPLocationRequest represents an IP location request
type GetIPLocationRequest struct {
	IPAddress string `json:"ip_address,omitempty"`
}

// GetIPLocation gets location information for an IP address
func (h *AdvancedSecurityHandler) GetIPLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req GetIPLocationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.IPAddress == "" {
		req.IPAddress = getClientIP(r)
	}

	location, err := h.advancedSecurityService.GetIPLocation(req.IPAddress)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to get IP location", err.Error())
		return
	}

	respondWithJSON(w, http.StatusOK, location)
}

