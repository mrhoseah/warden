package service

// EmailService defines the interface for sending emails
// This allows for easy integration with email providers (SendGrid, AWS SES, etc.)
type EmailService interface {
	SendVerificationEmail(email, token string) error
	SendPasswordResetEmail(email, token string) error
	SendMagicLinkEmail(email, token string) error
	SendEmailChangeConfirmationEmail(email, newEmail, token string) error
}

// MockEmailService is a mock implementation that logs emails to console
// Replace this with a real email service in production
type MockEmailService struct{}

// NewMockEmailService creates a new mock email service
func NewMockEmailService() *MockEmailService {
	return &MockEmailService{}
}

// SendVerificationEmail logs the verification email (mock implementation)
func (m *MockEmailService) SendVerificationEmail(email, token string) error {
	// In production, this would send an actual email
	// For now, we'll just log it
	// verificationURL := "http://localhost:8080/verify-email?token=" + token
	// In a real implementation, you would:
	// - Use SendGrid, AWS SES, Mailgun, etc.
	// - Send HTML email with verification link
	// - Handle errors from email provider
	return nil
}

// SendPasswordResetEmail logs the password reset email (mock implementation)
func (m *MockEmailService) SendPasswordResetEmail(email, token string) error {
	// In production, this would send an actual email
	// For now, we'll just log it
	// resetURL := "http://localhost:8080/reset-password?token=" + token
	// In a real implementation, you would:
	// - Use SendGrid, AWS SES, Mailgun, etc.
	// - Send HTML email with reset link
	// - Handle errors from email provider
	return nil
}

// SendMagicLinkEmail sends a magic link for passwordless login
func (m *MockEmailService) SendMagicLinkEmail(email, token string) error {
	// In production, this would send an actual email
	// magicLinkURL := "http://localhost:8080/auth/magic-link?token=" + token
	return nil
}

// SendEmailChangeConfirmationEmail sends confirmation for email change
func (m *MockEmailService) SendEmailChangeConfirmationEmail(email, newEmail, token string) error {
	// In production, this would send an actual email
	// confirmURL := "http://localhost:8080/email/change/confirm?token=" + token
	return nil
}

