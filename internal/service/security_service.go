package service

import (
	"errors"
	"regexp"
	"strings"
	"time"

	"authservice/internal/models"
)

// SecurityService handles security-related operations
type SecurityService struct {
	securityStore *models.SecurityStore
	loginHistory  *models.LoginHistoryStore
}

// NewSecurityService creates a new security service
func NewSecurityService(securityStore *models.SecurityStore, loginHistory *models.LoginHistoryStore) *SecurityService {
	return &SecurityService{
		securityStore: securityStore,
		loginHistory:  loginHistory,
	}
}

// PasswordStrength represents password strength validation result
type PasswordStrength struct {
	Valid   bool     `json:"valid"`
	Score   int      `json:"score"` // 0-4 (0=weak, 4=very strong)
	Issues  []string `json:"issues,omitempty"`
	Message string   `json:"message"`
}

// ValidatePasswordStrength validates password strength
func (s *SecurityService) ValidatePasswordStrength(password string) *PasswordStrength {
	result := &PasswordStrength{
		Valid:  true,
		Score:  0,
		Issues: []string{},
	}

	if len(password) < 8 {
		result.Valid = false
		result.Issues = append(result.Issues, "Password must be at least 8 characters long")
		return result
	}

	// Check for various character types
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`).MatchString(password)

	// Calculate score
	if hasLower {
		result.Score++
	} else {
		result.Issues = append(result.Issues, "Password should contain lowercase letters")
	}

	if hasUpper {
		result.Score++
	} else {
		result.Issues = append(result.Issues, "Password should contain uppercase letters")
	}

	if hasDigit {
		result.Score++
	} else {
		result.Issues = append(result.Issues, "Password should contain numbers")
	}

	if hasSpecial {
		result.Score++
	} else {
		result.Issues = append(result.Issues, "Password should contain special characters")
	}

	// Length bonus
	if len(password) >= 12 {
		result.Score++
	} else if len(password) >= 10 {
		// For 10-11 chars, we don't add to score but it's acceptable
	}

	// Check for common patterns
	commonPatterns := []string{"password", "123456", "qwerty", "abc123", "admin"}
	lowerPassword := strings.ToLower(password)
	for _, pattern := range commonPatterns {
		if strings.Contains(lowerPassword, pattern) {
			result.Score = 0
			result.Valid = false
			result.Issues = append(result.Issues, "Password contains common patterns")
			return result
		}
	}

	// Determine message
	switch {
	case result.Score >= 4:
		result.Message = "Very strong password"
	case result.Score >= 3:
		result.Message = "Strong password"
	case result.Score >= 2:
		result.Message = "Moderate password"
	case result.Score >= 1:
		result.Message = "Weak password"
	default:
		result.Message = "Very weak password"
		result.Valid = false
	}

	// Require at least score 2 for valid password
	if result.Score < 2 {
		result.Valid = false
	}

	return result
}

// CheckAccountLockout checks if an account is locked
func (s *SecurityService) CheckAccountLockout(email string) error {
	if s.securityStore.IsAccountLocked(email) {
		return errors.New("account is temporarily locked due to too many failed login attempts. Please try again later")
	}
	return nil
}

// RecordFailedLogin records a failed login attempt
func (s *SecurityService) RecordFailedLogin(email string) {
	s.securityStore.RecordFailedLogin(email)
}

// ClearFailedAttempts clears failed login attempts
func (s *SecurityService) ClearFailedAttempts(email string) {
	s.securityStore.ClearFailedAttempts(email)
}

// CheckRateLimit checks if an IP or email has exceeded rate limits
func (s *SecurityService) CheckRateLimit(key string, maxAttempts int, windowDuration time.Duration) error {
	if s.securityStore.CheckRateLimit(key, maxAttempts, windowDuration) {
		return errors.New("too many requests. Please try again later")
	}
	return nil
}

// BlacklistToken blacklists a token
func (s *SecurityService) BlacklistToken(token string, expiresAt time.Time) {
	s.securityStore.BlacklistToken(token, expiresAt)
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *SecurityService) IsTokenBlacklisted(token string) bool {
	return s.securityStore.IsTokenBlacklisted(token)
}

// DetectSuspiciousActivity detects suspicious login patterns
type SuspiciousActivity struct {
	Suspicious bool     `json:"suspicious"`
	Reasons    []string `json:"reasons,omitempty"`
	RiskScore  int      `json:"risk_score"` // 0-100
}

// DetectSuspiciousActivity analyzes login history for suspicious patterns
func (s *SecurityService) DetectSuspiciousActivity(userID int, ipAddress, userAgent, deviceType string) *SuspiciousActivity {
	activity := &SuspiciousActivity{
		Suspicious: false,
		Reasons:    []string{},
		RiskScore:  0,
	}

	// Get recent login history for user
	recentHistory := s.loginHistory.GetUserHistory(userID, 10)

	if len(recentHistory) == 0 {
		// First login - low risk
		return activity
	}

	// Check for new IP address
	ipSeenBefore := false
	for _, event := range recentHistory {
		if event.IPAddress == ipAddress && event.Success {
			ipSeenBefore = true
			break
		}
	}

	if !ipSeenBefore {
		activity.RiskScore += 30
		activity.Reasons = append(activity.Reasons, "Login from new IP address")
	}

	// Check for new device type
	deviceSeenBefore := false
	for _, event := range recentHistory {
		if event.DeviceType == deviceType && event.Success {
			deviceSeenBefore = true
			break
		}
	}

	if !deviceSeenBefore {
		activity.RiskScore += 20
		activity.Reasons = append(activity.Reasons, "Login from new device type")
	}

	// Check for rapid location change (different IPs in short time)
	if len(recentHistory) >= 2 {
		lastLogin := recentHistory[0]
		secondLastLogin := recentHistory[1]

		if lastLogin.IPAddress != secondLastLogin.IPAddress {
			timeDiff := lastLogin.CreatedAt.Sub(secondLastLogin.CreatedAt)
			if timeDiff < 1*time.Hour {
				activity.RiskScore += 40
				activity.Reasons = append(activity.Reasons, "Rapid location change detected")
			}
		}
	}

	// Check for multiple failed attempts
	failedCount := 0
	for _, event := range recentHistory {
		if !event.Success {
			failedCount++
		}
	}

	if failedCount >= 3 {
		activity.RiskScore += 25
		activity.Reasons = append(activity.Reasons, "Multiple recent failed login attempts")
	}

	// Mark as suspicious if risk score is high
	if activity.RiskScore >= 50 {
		activity.Suspicious = true
	}

	return activity
}

// GetSecurityStatus returns security status for a user
type SecurityStatus struct {
	FailedAttempts     int       `json:"failed_attempts"`
	IsLocked           bool      `json:"is_locked"`
	LockedUntil        *time.Time `json:"locked_until,omitempty"`
	LastFailedAttempt  *time.Time `json:"last_failed_attempt,omitempty"`
}

// GetSecurityStatus gets security status for an email
func (s *SecurityService) GetSecurityStatus(email string) *SecurityStatus {
	lockoutInfo := s.securityStore.GetLockoutInfo(email)
	
	status := &SecurityStatus{
		FailedAttempts: 0,
		IsLocked:       false,
	}

	if lockoutInfo != nil {
		status.FailedAttempts = lockoutInfo.FailedAttempts
		status.IsLocked = lockoutInfo.LockedUntil != nil && time.Now().Before(*lockoutInfo.LockedUntil)
		status.LockedUntil = lockoutInfo.LockedUntil
		status.LastFailedAttempt = &lockoutInfo.LastFailedAttempt
	}

	return status
}

