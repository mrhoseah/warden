package models

import (
	"sync"
	"time"
)

// AccountLockout represents account lockout information
type AccountLockout struct {
	Email              string
	FailedAttempts     int
	LockedUntil        *time.Time
	LastFailedAttempt  time.Time
}

// RateLimitEntry represents a rate limit entry for an IP or email
type RateLimitEntry struct {
	Key       string    // IP address or email
	Attempts  int
	WindowStart time.Time
	BlockedUntil *time.Time
}

// SecurityStore manages security-related data (rate limits, lockouts, etc.)
type SecurityStore struct {
	mu            sync.RWMutex
	lockouts      map[string]*AccountLockout // keyed by email
	rateLimits    map[string]*RateLimitEntry // keyed by IP or email
	blacklistedTokens map[string]time.Time   // token -> expiration time
}

// NewSecurityStore creates a new security store
func NewSecurityStore() *SecurityStore {
	return &SecurityStore{
		lockouts:         make(map[string]*AccountLockout),
		rateLimits:       make(map[string]*RateLimitEntry),
		blacklistedTokens: make(map[string]time.Time),
	}
}

// RecordFailedLogin records a failed login attempt
func (s *SecurityStore) RecordFailedLogin(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lockout, exists := s.lockouts[email]
	if !exists {
		lockout = &AccountLockout{
			Email:             email,
			FailedAttempts:    0,
			LastFailedAttempt: time.Now(),
		}
		s.lockouts[email] = lockout
	}

	lockout.FailedAttempts++
	lockout.LastFailedAttempt = time.Now()

	// Lock account after 5 failed attempts for 30 minutes
	if lockout.FailedAttempts >= 5 {
		lockedUntil := time.Now().Add(30 * time.Minute)
		lockout.LockedUntil = &lockedUntil
	}
}

// ClearFailedAttempts clears failed login attempts (on successful login)
func (s *SecurityStore) ClearFailedAttempts(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if lockout, exists := s.lockouts[email]; exists {
		lockout.FailedAttempts = 0
		lockout.LockedUntil = nil
	}
}

// IsAccountLocked checks if an account is currently locked
func (s *SecurityStore) IsAccountLocked(email string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	lockout, exists := s.lockouts[email]
	if !exists {
		return false
	}

	if lockout.LockedUntil == nil {
		return false
	}

	// If lockout expired, clear it
	if time.Now().After(*lockout.LockedUntil) {
		s.mu.RUnlock()
		s.mu.Lock()
		lockout.LockedUntil = nil
		lockout.FailedAttempts = 0
		s.mu.Unlock()
		s.mu.RLock()
		return false
	}

	return true
}

// GetFailedAttempts returns the number of failed attempts for an email
func (s *SecurityStore) GetFailedAttempts(email string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if lockout, exists := s.lockouts[email]; exists {
		return lockout.FailedAttempts
	}
	return 0
}

// GetLockoutInfo returns lockout information for an email
func (s *SecurityStore) GetLockoutInfo(email string) *AccountLockout {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if lockout, exists := s.lockouts[email]; exists {
		// Return a copy to avoid race conditions
		return &AccountLockout{
			Email:             lockout.Email,
			FailedAttempts:    lockout.FailedAttempts,
			LockedUntil:       lockout.LockedUntil,
			LastFailedAttempt: lockout.LastFailedAttempt,
		}
	}
	return nil
}

// CheckRateLimit checks if a key (IP or email) has exceeded rate limits
// Returns true if rate limited, false otherwise
func (s *SecurityStore) CheckRateLimit(key string, maxAttempts int, windowDuration time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.rateLimits[key]
	now := time.Now()

	if !exists {
		entry = &RateLimitEntry{
			Key:        key,
			Attempts:   1,
			WindowStart: now,
		}
		s.rateLimits[key] = entry
		return false
	}

	// Check if blocked
	if entry.BlockedUntil != nil && now.Before(*entry.BlockedUntil) {
		return true
	}

	// Reset window if expired
	if now.Sub(entry.WindowStart) > windowDuration {
		entry.Attempts = 1
		entry.WindowStart = now
		entry.BlockedUntil = nil
		return false
	}

	entry.Attempts++

	// Block if exceeded max attempts
	if entry.Attempts > maxAttempts {
		blockedUntil := now.Add(15 * time.Minute) // Block for 15 minutes
		entry.BlockedUntil = &blockedUntil
		return true
	}

	return false
}

// BlacklistToken adds a token to the blacklist
func (s *SecurityStore) BlacklistToken(token string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.blacklistedTokens[token] = expiresAt
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *SecurityStore) IsTokenBlacklisted(token string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expiresAt, exists := s.blacklistedTokens[token]
	if !exists {
		return false
	}

	// If expired, remove it
	if time.Now().After(expiresAt) {
		s.mu.RUnlock()
		s.mu.Lock()
		delete(s.blacklistedTokens, token)
		s.mu.Unlock()
		s.mu.RLock()
		return false
	}

	return true
}

// CleanupExpiredEntries removes expired entries (should be called periodically)
func (s *SecurityStore) CleanupExpiredEntries() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Clean up expired blacklisted tokens
	for token, expiresAt := range s.blacklistedTokens {
		if now.After(expiresAt) {
			delete(s.blacklistedTokens, token)
		}
	}

	// Clean up expired rate limit entries
	for key, entry := range s.rateLimits {
		if entry.BlockedUntil != nil && now.After(*entry.BlockedUntil) {
			// Reset if block expired
			entry.BlockedUntil = nil
			entry.Attempts = 0
		}
		// Remove old entries (older than 1 hour)
		if now.Sub(entry.WindowStart) > time.Hour {
			delete(s.rateLimits, key)
		}
	}

	// Clean up expired lockouts
	for email, lockout := range s.lockouts {
		if lockout.LockedUntil != nil && now.After(*lockout.LockedUntil) {
			lockout.LockedUntil = nil
			lockout.FailedAttempts = 0
		}
		// Remove lockouts with no recent activity (older than 24 hours)
		if now.Sub(lockout.LastFailedAttempt) > 24*time.Hour && lockout.FailedAttempts == 0 {
			delete(s.lockouts, email)
		}
	}
}

