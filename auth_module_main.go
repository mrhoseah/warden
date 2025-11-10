package main

import (
	"fmt"
	"log"
	"net/http"

	"authservice/internal/handler"
	"authservice/internal/middleware"
	"authservice/internal/models"
	"authservice/internal/service"

	_ "authservice/docs" // swagger docs
	httpSwagger "github.com/swaggo/http-swagger"
)

// @title           Authentication Service API
// @version         1.0
// @description     A production-ready authentication microservice with modern features including 2FA, magic links, session management, and API keys.
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.url    http://www.example.com/support
// @contact.email  support@example.com

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

func main() {
	// Initialize components following clean architecture
	userStore := models.NewUserStore()
	sessionStore := models.NewSessionStore()
	loginHistoryStore := models.NewLoginHistoryStore()
	apiKeyStore := models.NewAPIKeyStore()
	
	emailService := service.NewMockEmailService()
	authService := service.NewAuthService(userStore, emailService)
	modernAuthService := service.NewModernAuthService(authService, sessionStore, loginHistoryStore, apiKeyStore, userStore)
	
	authHandler := handler.NewHandler(authService)
	modernAuthHandler := handler.NewModernAuthHandler(modernAuthService)
	authMiddleware := middleware.NewAuthMiddleware(authService)

	// Setup routes
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/register", authHandler.Register)
	mux.HandleFunc("/login", authHandler.Login)
	mux.HandleFunc("/login/2fa", authHandler.LoginWithTwoFactor)
	mux.HandleFunc("/refresh", authHandler.Refresh)
	mux.HandleFunc("/password/reset", authHandler.RequestPasswordReset)
	mux.HandleFunc("/password/reset/confirm", authHandler.ResetPassword)
	mux.HandleFunc("/email/verify", authHandler.VerifyEmail)
	mux.HandleFunc("/email/resend", authHandler.ResendVerificationEmail)
	mux.HandleFunc("/oauth/callback", authHandler.OAuthCallback)
	
	// Modern auth public endpoints
	mux.HandleFunc("/auth/magic-link/request", modernAuthHandler.RequestMagicLink)
	mux.HandleFunc("/auth/magic-link", modernAuthHandler.LoginWithMagicLink)
	mux.HandleFunc("/email/change/confirm", modernAuthHandler.ConfirmEmailChange)

	// Protected endpoints (requires authentication)
	mux.HandleFunc("/user", authMiddleware.RequireAuth(authHandler.User))
	mux.HandleFunc("/2fa/enable", authMiddleware.RequireAuth(authHandler.EnableTwoFactor))
	mux.HandleFunc("/2fa/disable", authMiddleware.RequireAuth(authHandler.DisableTwoFactor))
	
	// Modern auth protected endpoints
	mux.HandleFunc("/sessions", authMiddleware.RequireAuth(modernAuthHandler.GetSessions))
	mux.HandleFunc("/sessions/revoke", authMiddleware.RequireAuth(modernAuthHandler.RevokeSession))
	mux.HandleFunc("/sessions/revoke-all", authMiddleware.RequireAuth(modernAuthHandler.RevokeAllSessions))
	mux.HandleFunc("/sessions/trust", authMiddleware.RequireAuth(modernAuthHandler.MarkDeviceAsTrusted))
	mux.HandleFunc("/login-history", authMiddleware.RequireAuth(modernAuthHandler.GetLoginHistory))
	mux.HandleFunc("/profile", authMiddleware.RequireAuth(modernAuthHandler.UpdateProfile))
	mux.HandleFunc("/password/change", authMiddleware.RequireAuth(modernAuthHandler.ChangePassword))
	mux.HandleFunc("/email/change", authMiddleware.RequireAuth(modernAuthHandler.RequestEmailChange))
	mux.HandleFunc("/account/delete", authMiddleware.RequireAuth(modernAuthHandler.DeleteAccount))
	mux.HandleFunc("/api-keys", authMiddleware.RequireAuth(modernAuthHandler.GetAPIKeys))
	mux.HandleFunc("/api-keys/generate", authMiddleware.RequireAuth(modernAuthHandler.GenerateAPIKey))
	mux.HandleFunc("/api-keys/revoke", authMiddleware.RequireAuth(modernAuthHandler.RevokeAPIKey))

	// Swagger documentation
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	// Start server
	port := ":8080"
	fmt.Printf("🚀 Authentication Service starting on http://localhost%s\n", port)
	fmt.Println("📝 Available endpoints:")
	fmt.Println("\n🔓 Public Endpoints:")
	fmt.Println("   POST   /register              - Register a new user")
	fmt.Println("   POST   /login                 - Login with credentials")
	fmt.Println("   POST   /login/2fa             - Login with 2FA code")
	fmt.Println("   POST   /refresh               - Refresh access token")
	fmt.Println("   POST   /password/reset        - Request password reset")
	fmt.Println("   POST   /password/reset/confirm - Confirm password reset")
	fmt.Println("   POST   /email/verify          - Verify email address")
	fmt.Println("   POST   /email/resend          - Resend verification email")
	fmt.Println("   POST   /oauth/callback        - OAuth authentication callback")
	fmt.Println("\n🔒 Protected Endpoints (require Bearer token):")
	fmt.Println("   GET    /user                  - Get authenticated user")
	fmt.Println("   POST   /2fa/enable            - Enable two-factor authentication")
	fmt.Println("   POST   /2fa/disable           - Disable two-factor authentication")
	fmt.Println("\n📱 Modern Auth Features:")
	fmt.Println("   POST   /auth/magic-link/request - Request passwordless login link")
	fmt.Println("   POST   /auth/magic-link         - Login with magic link")
	fmt.Println("   GET    /sessions                - Get active sessions")
	fmt.Println("   POST   /sessions/revoke         - Revoke a session")
	fmt.Println("   POST   /sessions/revoke-all     - Revoke all sessions")
	fmt.Println("   POST   /sessions/trust          - Mark device as trusted")
	fmt.Println("   GET    /login-history           - Get login history")
	fmt.Println("   PUT    /profile                 - Update profile")
	fmt.Println("   POST   /password/change         - Change password")
	fmt.Println("   POST   /email/change            - Request email change")
	fmt.Println("   DELETE /account/delete          - Delete account")
	fmt.Println("   GET    /api-keys                - Get API keys")
	fmt.Println("   POST   /api-keys/generate       - Generate API key")
	fmt.Println("   POST   /api-keys/revoke         - Revoke API key")
	fmt.Println("\n📚 API Documentation:")
	fmt.Println("   GET    /swagger/index.html      - Swagger UI documentation")

	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}

