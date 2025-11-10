package models

import (
	"sync"
	"time"
)

// Session represents an active user session
type Session struct {
	ID           string    `json:"id"`
	UserID       int       `json:"user_id"`
	DeviceName   string    `json:"device_name"`
	DeviceType   string    `json:"device_type"` // "mobile", "desktop", "tablet", "unknown"
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	IsTrusted    bool      `json:"is_trusted"`
	LastActivity time.Time `json:"last_activity"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SessionStore manages active sessions
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session // keyed by session ID
	byUser   map[int][]string    // user ID -> session IDs
	nextID   int
}

// NewSessionStore creates a new session store
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		byUser:   make(map[int][]string),
		nextID:   1,
	}
}

// CreateSession creates a new session
func (s *SessionStore) CreateSession(userID int, deviceName, deviceType, ipAddress, userAgent string, trusted bool) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	sessionID := generateSessionID()

	session := &Session{
		ID:           sessionID,
		UserID:       userID,
		DeviceName:   deviceName,
		DeviceType:   deviceType,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		IsTrusted:    trusted,
		LastActivity: now,
		CreatedAt:    now,
		ExpiresAt:    now.Add(7 * 24 * time.Hour), // 7 days
	}

	s.sessions[sessionID] = session
	s.byUser[userID] = append(s.byUser[userID], sessionID)

	return session
}

// GetSession retrieves a session by ID
func (s *SessionStore) GetSession(sessionID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists || time.Now().After(session.ExpiresAt) {
		return nil, false
	}

	return session, true
}

// GetUserSessions retrieves all active sessions for a user
func (s *SessionStore) GetUserSessions(userID int) []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionIDs := s.byUser[userID]
	sessions := make([]*Session, 0, len(sessionIDs))
	now := time.Now()

	for _, id := range sessionIDs {
		if session, exists := s.sessions[id]; exists && now.Before(session.ExpiresAt) {
			sessions = append(sessions, session)
		}
	}

	return sessions
}

// RevokeSession revokes a session
func (s *SessionStore) RevokeSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}

	delete(s.sessions, sessionID)

	// Remove from user's session list
	sessionIDs := s.byUser[session.UserID]
	for i, id := range sessionIDs {
		if id == sessionID {
			s.byUser[session.UserID] = append(sessionIDs[:i], sessionIDs[i+1:]...)
			break
		}
	}

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user
func (s *SessionStore) RevokeAllUserSessions(userID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sessionIDs := s.byUser[userID]
	for _, id := range sessionIDs {
		delete(s.sessions, id)
	}
	delete(s.byUser, userID)

	return nil
}

// UpdateSessionActivity updates the last activity time
func (s *SessionStore) UpdateSessionActivity(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}

	session.LastActivity = time.Now()
	return nil
}

// MarkSessionAsTrusted marks a session as trusted
func (s *SessionStore) MarkSessionAsTrusted(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return ErrSessionNotFound
	}

	session.IsTrusted = true
	return nil
}

func generateSessionID() string {
	// Simple session ID generation - in production, use crypto/rand
	return time.Now().Format("20060102150405") + "-" + randomString(16)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[i%len(charset)]
	}
	return string(b)
}

