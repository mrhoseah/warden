package models

import "errors"

var (
	ErrUserNotFound          = errors.New("user not found")
	ErrUserAlreadyExists     = errors.New("user already exists")
	ErrInvalidToken          = errors.New("invalid token")
	ErrTokenExpired          = errors.New("token expired")
	ErrEmailAlreadyVerified  = errors.New("email already verified")
	ErrEmailNotVerified      = errors.New("email not verified")
	ErrSessionNotFound       = errors.New("session not found")
	ErrAPIKeyNotFound        = errors.New("api key not found")
	ErrInvalidAPIKey         = errors.New("invalid api key")
)

