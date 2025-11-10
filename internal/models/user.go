package models

import (
	"sync"
	"time"
)

// User represents a user in the system
type User struct {
	ID                    int        `json:"id"`
	Email                 string     `json:"email"`
	Name                  string     `json:"name,omitempty"`
	PasswordHash          string     `json:"-"` // Never serialize password hash
	EmailVerified         bool       `json:"email_verified"`
	EmailVerifiedAt       *time.Time `json:"email_verified_at,omitempty"`
	EmailChangeToken      string     `json:"-"` // Never serialize
	EmailChangeNewEmail   string     `json:"-"` // Never serialize
	EmailChangeExpires    *time.Time `json:"-"` // Never serialize
	PasswordResetToken    string     `json:"-"` // Never serialize reset token
	PasswordResetExpires  *time.Time `json:"-"` // Never serialize
	MagicLinkToken        string     `json:"-"` // Never serialize magic link token
	MagicLinkExpires      *time.Time `json:"-"` // Never serialize
	TwoFactorEnabled      bool       `json:"two_factor_enabled"`
	TOTPSecret            string     `json:"-"` // Never serialize TOTP secret
	BackupCodes           []string   `json:"-"` // Never serialize backup codes
	Active                bool       `json:"active"` // Account status
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// UserStore is an in-memory store for users (can be replaced with a database)
type UserStore struct {
	mu    sync.RWMutex
	users map[string]*User // keyed by email
	nextID int
}

// NewUserStore creates a new in-memory user store
func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*User),
		nextID: 1,
	}
}

// CreateUser adds a new user to the store
func (s *UserStore) CreateUser(email, passwordHash string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if user already exists
	if _, exists := s.users[email]; exists {
		return nil, ErrUserAlreadyExists
	}

	now := time.Now()
	user := &User{
		ID:            s.nextID,
		Email:         email,
		PasswordHash:  passwordHash,
		EmailVerified: false, // New users need to verify email
		Active:        true,  // New users are active by default
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	s.users[email] = user
	s.nextID++

	return user, nil
}

// GetUserByEmail retrieves a user by email
func (s *UserStore) GetUserByEmail(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[email]
	if !exists {
		return nil, ErrUserNotFound
	}

	return user, nil
}

// GetUserByID retrieves a user by ID
func (s *UserStore) GetUserByID(id int) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.ID == id {
			return user, nil
		}
	}

	return nil, ErrUserNotFound
}

// UpdateUser updates user fields
func (s *UserStore) UpdateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.Email]; !exists {
		return ErrUserNotFound
	}

	user.UpdatedAt = time.Now()
	s.users[user.Email] = user
	return nil
}

// GetUserByResetToken finds a user by their password reset token
func (s *UserStore) GetUserByResetToken(token string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.PasswordResetToken == token && user.PasswordResetToken != "" {
			return user, nil
		}
	}

	return nil, ErrUserNotFound
}

// GetUserByMagicLinkToken finds a user by their magic link token
func (s *UserStore) GetUserByMagicLinkToken(token string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.MagicLinkToken == token && user.MagicLinkToken != "" {
			return user, nil
		}
	}

	return nil, ErrUserNotFound
}

// GetUserByEmailChangeToken finds a user by their email change token
func (s *UserStore) GetUserByEmailChangeToken(token string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.EmailChangeToken == token && user.EmailChangeToken != "" {
			return user, nil
		}
	}

	return nil, ErrUserNotFound
}

