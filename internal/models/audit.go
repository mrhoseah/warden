package models

import (
	"sync"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	AuditEventLogin           AuditEventType = "login"
	AuditEventLogout          AuditEventType = "logout"
	AuditEventPasswordChange  AuditEventType = "password_change"
	AuditEventEmailChange     AuditEventType = "email_change"
	AuditEvent2FAEnabled      AuditEventType = "2fa_enabled"
	AuditEvent2FADisabled    AuditEventType = "2fa_disabled"
	AuditEventTokenRevoked    AuditEventType = "token_revoked"
	AuditEventAccountLocked   AuditEventType = "account_locked"
	AuditEventAccountUnlocked AuditEventType = "account_unlocked"
	AuditEventSuspiciousActivity AuditEventType = "suspicious_activity"
	AuditEventSessionRevoked  AuditEventType = "session_revoked"
	AuditEventAPIKeyGenerated AuditEventType = "api_key_generated"
	AuditEventAPIKeyRevoked   AuditEventType = "api_key_revoked"
)

// AuditEvent represents an audit log entry
type AuditEvent struct {
	ID          int           `json:"id"`
	UserID      int           `json:"user_id"`
	EventType   AuditEventType `json:"event_type"`
	IPAddress   string        `json:"ip_address"`
	UserAgent   string        `json:"user_agent"`
	DeviceType  string        `json:"device_type"`
	Details     string        `json:"details"` // JSON string with additional details
	RiskScore   int           `json:"risk_score"` // 0-100
	Success     bool          `json:"success"`
	CreatedAt   time.Time     `json:"created_at"`
}

// AuditStore manages audit logs
type AuditStore struct {
	mu     sync.RWMutex
	events []*AuditEvent
	byUser map[int][]*AuditEvent
	nextID int
	maxSize int
}

// NewAuditStore creates a new audit store
func NewAuditStore() *AuditStore {
	return &AuditStore{
		events:  make([]*AuditEvent, 0),
		byUser:  make(map[int][]*AuditEvent),
		nextID:  1,
		maxSize: 50000, // Keep last 50k events
	}
}

// AddEvent adds an audit event
func (s *AuditStore) AddEvent(userID int, eventType AuditEventType, ipAddress, userAgent, deviceType, details string, riskScore int, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	event := &AuditEvent{
		ID:         s.nextID,
		UserID:     userID,
		EventType:  eventType,
		IPAddress:  ipAddress,
		UserAgent:  userAgent,
		DeviceType: deviceType,
		Details:    details,
		RiskScore:  riskScore,
		Success:    success,
		CreatedAt:  time.Now(),
	}

	s.events = append(s.events, event)
	s.byUser[userID] = append(s.byUser[userID], event)
	s.nextID++

	// Trim if too large
	if len(s.events) > s.maxSize {
		oldest := s.events[0]
		s.events = s.events[1:]
		// Remove from user's history too
		userEvents := s.byUser[oldest.UserID]
		if len(userEvents) > 0 && userEvents[0].ID == oldest.ID {
			s.byUser[oldest.UserID] = userEvents[1:]
		}
	}
}

// GetUserAuditLog retrieves audit logs for a user
func (s *AuditStore) GetUserAuditLog(userID int, limit int) []*AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := s.byUser[userID]
	if len(events) > limit {
		return events[len(events)-limit:]
	}
	return events
}

// GetAuditLog retrieves all audit logs (admin function)
func (s *AuditStore) GetAuditLog(limit int) []*AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.events) > limit {
		return s.events[len(s.events)-limit:]
	}
	return s.events
}

