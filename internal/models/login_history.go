package models

import (
	"sync"
	"time"
)

// LoginEvent represents a login attempt or successful login
type LoginEvent struct {
	ID          int       `json:"id"`
	UserID      int       `json:"user_id"`
	Email       string    `json:"email"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	DeviceType  string    `json:"device_type"`
	Success     bool      `json:"success"`
	FailureReason string  `json:"failure_reason,omitempty"`
	Method      string    `json:"method"` // "password", "magic_link", "oauth", "2fa"
	CreatedAt   time.Time `json:"created_at"`
}

// LoginHistoryStore manages login history
type LoginHistoryStore struct {
	mu      sync.RWMutex
	events  []*LoginEvent
	byUser  map[int][]*LoginEvent
	nextID  int
	maxSize int // Maximum number of events to keep
}

// NewLoginHistoryStore creates a new login history store
func NewLoginHistoryStore() *LoginHistoryStore {
	return &LoginHistoryStore{
		events:  make([]*LoginEvent, 0),
		byUser:  make(map[int][]*LoginEvent),
		nextID:  1,
		maxSize: 10000, // Keep last 10k events
	}
}

// AddEvent adds a login event
func (s *LoginHistoryStore) AddEvent(userID int, email, ipAddress, userAgent, deviceType string, success bool, failureReason, method string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	event := &LoginEvent{
		ID:           s.nextID,
		UserID:       userID,
		Email:        email,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		DeviceType:   deviceType,
		Success:      success,
		FailureReason: failureReason,
		Method:       method,
		CreatedAt:    time.Now(),
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

// GetUserHistory retrieves login history for a user
func (s *LoginHistoryStore) GetUserHistory(userID int, limit int) []*LoginEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := s.byUser[userID]
	if limit > 0 && limit < len(events) {
		// Return most recent events
		start := len(events) - limit
		result := make([]*LoginEvent, limit)
		copy(result, events[start:])
		return result
	}

	return events
}

// GetRecentEvents retrieves recent login events across all users
func (s *LoginHistoryStore) GetRecentEvents(limit int) []*LoginEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit > len(s.events) {
		limit = len(s.events)
	}

	start := len(s.events) - limit
	result := make([]*LoginEvent, limit)
	copy(result, s.events[start:])
	return result
}

