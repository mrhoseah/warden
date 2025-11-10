package models

import (
	"sync"
	"time"
)

// APIKey represents an API key for service-to-service authentication
type APIKey struct {
	ID          int       `json:"id"`
	UserID      int       `json:"user_id"`
	Name        string    `json:"name"`
	KeyHash     string    `json:"-"` // Never serialize the actual key
	Prefix      string    `json:"prefix"` // First 8 chars for display
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Revoked     bool      `json:"revoked"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

// APIKeyStore manages API keys
type APIKeyStore struct {
	mu      sync.RWMutex
	keys    map[string]*APIKey // keyed by key hash
	byUser  map[int][]*APIKey  // user ID -> API keys
	byPrefix map[string]*APIKey // prefix -> API key (for quick lookup)
	nextID  int
}

// NewAPIKeyStore creates a new API key store
func NewAPIKeyStore() *APIKeyStore {
	return &APIKeyStore{
		keys:     make(map[string]*APIKey),
		byUser:   make(map[int][]*APIKey),
		byPrefix: make(map[string]*APIKey),
		nextID:   1,
	}
}

// CreateAPIKey creates a new API key
func (s *APIKeyStore) CreateAPIKey(userID int, name string, keyHash, prefix string, expiresAt *time.Time) *APIKey {
	s.mu.Lock()
	defer s.mu.Unlock()

	apiKey := &APIKey{
		ID:        s.nextID,
		UserID:    userID,
		Name:      name,
		KeyHash:   keyHash,
		Prefix:    prefix,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	s.keys[keyHash] = apiKey
	s.byUser[userID] = append(s.byUser[userID], apiKey)
	s.byPrefix[prefix] = apiKey
	s.nextID++

	return apiKey
}

// GetAPIKeyByHash retrieves an API key by its hash
func (s *APIKeyStore) GetAPIKeyByHash(keyHash string) (*APIKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keys[keyHash]
	if !exists || key.Revoked {
		return nil, false
	}

	// Check expiration
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, false
	}

	return key, true
}

// GetUserAPIKeys retrieves all API keys for a user
func (s *APIKeyStore) GetUserAPIKeys(userID int) []*APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.byUser[userID]
}

// RevokeAPIKey revokes an API key
func (s *APIKeyStore) RevokeAPIKey(keyHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keys[keyHash]
	if !exists {
		return ErrAPIKeyNotFound
	}

	key.Revoked = true
	now := time.Now()
	key.RevokedAt = &now

	return nil
}

// UpdateLastUsed updates the last used timestamp
func (s *APIKeyStore) UpdateLastUsed(keyHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keys[keyHash]
	if !exists {
		return ErrAPIKeyNotFound
	}

	now := time.Now()
	key.LastUsedAt = &now
	return nil
}

// GetAPIKeyByPrefix retrieves an API key by its prefix
func (s *APIKeyStore) GetAPIKeyByPrefix(prefix string) (*APIKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.byPrefix[prefix]
	if !exists || key.Revoked {
		return nil, false
	}

	// Check expiration
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, false
	}

	return key, true
}

