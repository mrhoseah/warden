package service

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"authservice/internal/models"
)

// AdvancedSecurityService provides advanced security features
type AdvancedSecurityService struct {
	securityStore    *models.SecurityStore
	auditStore       *models.AuditStore
	sessionStore     *models.SessionStore
	loginHistory     *models.LoginHistoryStore
	securityService  *SecurityService // For password strength validation
	httpClient       *http.Client
}

// NewAdvancedSecurityService creates a new advanced security service
func NewAdvancedSecurityService(securityStore *models.SecurityStore, auditStore *models.AuditStore, sessionStore *models.SessionStore, loginHistory *models.LoginHistoryStore, securityService *SecurityService) *AdvancedSecurityService {
	return &AdvancedSecurityService{
		securityStore:   securityStore,
		auditStore:      auditStore,
		sessionStore:    sessionStore,
		loginHistory:    loginHistory,
		securityService: securityService,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// PasswordBreachResult represents the result of password breach checking
type PasswordBreachResult struct {
	Breached     bool   `json:"breached"`
	BreachCount  int    `json:"breach_count"`
	Message      string `json:"message"`
	Checked      bool   `json:"checked"`
}

// CheckPasswordBreach checks if a password has been in a data breach using Have I Been Pwned API (k-anonymity)
func (s *AdvancedSecurityService) CheckPasswordBreach(password string) (*PasswordBreachResult, error) {
	// Hash the password with SHA-1
	hash := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))

	// Use k-anonymity: only send first 5 chars of hash
	prefix := hashStr[:5]
	suffix := hashStr[5:]

	// Call Have I Been Pwned API
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return &PasswordBreachResult{Checked: false, Message: "Failed to check password breach"}, err
	}

	req.Header.Set("User-Agent", "Warden-Auth-Service")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		// If API is unavailable, don't fail - just return unchecked
		return &PasswordBreachResult{Checked: false, Message: "Breach check service unavailable"}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &PasswordBreachResult{Checked: false, Message: "Breach check service returned error"}, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &PasswordBreachResult{Checked: false, Message: "Failed to read breach check response"}, err
	}

	// Parse response - format is "SUFFIX:COUNT" per line
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) == 2 && strings.EqualFold(parts[0], suffix) {
			var count int
			fmt.Sscanf(parts[1], "%d", &count)
			return &PasswordBreachResult{
				Breached:    true,
				BreachCount: count,
				Message:     fmt.Sprintf("This password has appeared in %d data breaches", count),
				Checked:     true,
			}, nil
		}
	}

	return &PasswordBreachResult{
		Breached: false,
		Message:  "Password not found in known breaches",
		Checked:  true,
	}, nil
}

// AdaptiveAuthResult represents the result of adaptive authentication
type AdaptiveAuthResult struct {
	RequiresAdditionalAuth bool     `json:"requires_additional_auth"`
	RiskScore              int      `json:"risk_score"` // 0-100
	Reasons                []string `json:"reasons"`
	RecommendedActions     []string `json:"recommended_actions"`
}

// EvaluateAdaptiveAuth evaluates risk and determines if additional authentication is required
func (s *AdvancedSecurityService) EvaluateAdaptiveAuth(userID int, ipAddress, userAgent, deviceType string) *AdaptiveAuthResult {
	result := &AdaptiveAuthResult{
		RequiresAdditionalAuth: false,
		RiskScore:              0,
		Reasons:                []string{},
		RecommendedActions:     []string{},
	}

	// Get recent login history
	recentHistory := s.loginHistory.GetUserHistory(userID, 10)

	// Check 1: New IP address
	ipSeenBefore := false
	for _, event := range recentHistory {
		if event.IPAddress == ipAddress && event.Success {
			ipSeenBefore = true
			break
		}
	}
	if !ipSeenBefore {
		result.RiskScore += 30
		result.Reasons = append(result.Reasons, "Login from new IP address")
		result.RecommendedActions = append(result.RecommendedActions, "Verify via email")
	}

	// Check 2: New device type
	deviceSeenBefore := false
	for _, event := range recentHistory {
		if event.DeviceType == deviceType && event.Success {
			deviceSeenBefore = true
			break
		}
	}
	if !deviceSeenBefore {
		result.RiskScore += 20
		result.Reasons = append(result.Reasons, "Login from new device type")
	}

	// Check 3: Rapid location change
	if len(recentHistory) >= 2 {
		lastLogin := recentHistory[0]
		secondLastLogin := recentHistory[1]
		if lastLogin.IPAddress != secondLastLogin.IPAddress {
			timeDiff := lastLogin.CreatedAt.Sub(secondLastLogin.CreatedAt)
			if timeDiff < 1*time.Hour {
				result.RiskScore += 40
				result.Reasons = append(result.Reasons, "Rapid location change detected")
				result.RecommendedActions = append(result.RecommendedActions, "Require 2FA verification")
			}
		}
	}

	// Check 4: Multiple failed attempts
	failedCount := 0
	for _, event := range recentHistory {
		if !event.Success {
			failedCount++
		}
	}
	if failedCount >= 3 {
		result.RiskScore += 25
		result.Reasons = append(result.Reasons, "Multiple recent failed login attempts")
		result.RecommendedActions = append(result.RecommendedActions, "Account may be compromised")
	}

	// Check 5: Unusual time (login outside normal hours - simplified check)
	now := time.Now()
	hour := now.Hour()
	if hour < 6 || hour > 23 {
		result.RiskScore += 15
		result.Reasons = append(result.Reasons, "Login during unusual hours")
	}

	// Determine if additional auth is required
	if result.RiskScore >= 50 {
		result.RequiresAdditionalAuth = true
	}

	return result
}

// SessionHijackingResult represents session hijacking detection result
type SessionHijackingResult struct {
	Suspicious     bool     `json:"suspicious"`
	RiskScore      int      `json:"risk_score"`
	Reasons        []string `json:"reasons"`
	ActiveSessions int      `json:"active_sessions"`
}

// DetectSessionHijacking detects potential session hijacking
func (s *AdvancedSecurityService) DetectSessionHijacking(userID int, currentIP, currentUserAgent string) *SessionHijackingResult {
	result := &SessionHijackingResult{
		Suspicious: false,
		RiskScore:  0,
		Reasons:    []string{},
	}

	// Get all active sessions for user
	sessions := s.sessionStore.GetUserSessions(userID)
	result.ActiveSessions = len(sessions)

	// Check for concurrent sessions from different IPs
	ipSet := make(map[string]bool)
	for _, session := range sessions {
		if session.IPAddress != "" {
			ipSet[session.IPAddress] = true
		}
	}

	if len(ipSet) > 3 {
		result.RiskScore += 40
		result.Reasons = append(result.Reasons, fmt.Sprintf("Active sessions from %d different IP addresses", len(ipSet)))
		result.Suspicious = true
	}

	// Check if current session IP differs from most recent successful login
	recentHistory := s.loginHistory.GetUserHistory(userID, 5)
	if len(recentHistory) > 0 {
		lastSuccessfulIP := ""
		for _, event := range recentHistory {
			if event.Success && event.IPAddress != "" {
				lastSuccessfulIP = event.IPAddress
				break
			}
		}
		if lastSuccessfulIP != "" && lastSuccessfulIP != currentIP {
			result.RiskScore += 30
			result.Reasons = append(result.Reasons, "Current IP differs from last successful login IP")
			if result.RiskScore >= 50 {
				result.Suspicious = true
			}
		}
	}

	// Check for sessions with different user agents
	userAgentSet := make(map[string]bool)
	for _, session := range sessions {
		if session.UserAgent != "" {
			userAgentSet[session.UserAgent] = true
		}
	}

	if len(userAgentSet) > 2 {
		result.RiskScore += 20
		result.Reasons = append(result.Reasons, "Active sessions with different user agents")
	}

	if result.RiskScore >= 50 {
		result.Suspicious = true
	}

	return result
}

// LogAuditEvent logs an audit event
func (s *AdvancedSecurityService) LogAuditEvent(userID int, eventType models.AuditEventType, ipAddress, userAgent, deviceType, details string, riskScore int, success bool) {
	s.auditStore.AddEvent(userID, eventType, ipAddress, userAgent, deviceType, details, riskScore, success)
}

// GetAuditLog retrieves audit logs for a user
func (s *AdvancedSecurityService) GetAuditLog(userID int, limit int) []*models.AuditEvent {
	return s.auditStore.GetUserAuditLog(userID, limit)
}

// IPLocation represents IP geolocation information
type IPLocation struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	Region      string `json:"region"`
	City        string `json:"city"`
	ISP         string `json:"isp"`
	IsVPN       bool   `json:"is_vpn"`
	IsProxy     bool   `json:"is_proxy"`
	IsTor       bool   `json:"is_tor"`
	RiskScore   int    `json:"risk_score"`
}

// GetIPLocation gets location information for an IP address (simplified version)
func (s *AdvancedSecurityService) GetIPLocation(ipAddress string) (*IPLocation, error) {
	// In a real implementation, you would call a geolocation API
	// For now, we'll return a simplified version
	// You can integrate with services like ipapi.co, ip-api.com, or MaxMind GeoIP2

	// Simplified implementation - in production, use a real geolocation service
	location := &IPLocation{
		IP:        ipAddress,
		Country:   "Unknown",
		Region:    "Unknown",
		City:      "Unknown",
		ISP:       "Unknown",
		IsVPN:     false,
		IsProxy:   false,
		IsTor:     false,
		RiskScore: 0,
	}

	// Basic checks
	if strings.HasPrefix(ipAddress, "127.") || ipAddress == "::1" {
		location.City = "Local"
		location.Country = "Local"
	}

	// In production, you would:
	// 1. Call a geolocation API
	// 2. Check VPN/proxy/Tor databases
	// 3. Calculate risk based on location history

	return location, nil
}

// ValidatePasswordWithBreachCheck validates password strength and checks for breaches
func (s *AdvancedSecurityService) ValidatePasswordWithBreachCheck(password string) (*PasswordStrength, *PasswordBreachResult, error) {
	// First check password strength
	var strength *PasswordStrength
	if s.securityService != nil {
		strength = s.securityService.ValidatePasswordStrength(password)
	} else {
		// Fallback if security service not available
		strength = &PasswordStrength{
			Valid:   len(password) >= 8,
			Score:   0,
			Issues:  []string{},
			Message: "Password strength not validated",
		}
		if len(password) < 8 {
			strength.Issues = []string{"Password must be at least 8 characters"}
		}
	}

	// Check for breach
	breachResult, err := s.CheckPasswordBreach(password)
	if err != nil {
		// If breach check fails, still return strength but note the issue
		return strength, nil, err
	}

	return strength, breachResult, nil
}

