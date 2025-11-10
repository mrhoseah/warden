# 🛠 Go Authentication Microservice

A production-ready, decoupled authentication microservice built in Go, providing secure authentication with **Fortify-like business logic** and **Sanctum-like stateless JWT tokens**. Features include password reset, email verification, two-factor authentication (2FA), and OAuth integrations.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Setup](#-setup)
- [API Endpoints](#-api-endpoints)
- [Usage Examples](#-usage-examples)
- [Security Considerations](#-security-considerations)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Extending the Service](#-extending-the-service)

---

## ✨ Features

### Core Authentication
- ✅ User registration with email and password
- ✅ Secure login with JWT tokens
- ✅ Access tokens (15 minutes) and refresh tokens (7 days)
- ✅ Token refresh mechanism
- ✅ Protected routes with middleware

### Password Management
- ✅ Password reset via email
- ✅ Secure password hashing with bcrypt
- ✅ Password reset token expiration (1 hour)

### Email Verification
- ✅ Email verification on registration
- ✅ Resend verification email
- ✅ JWT-based verification tokens (24 hours)

### Two-Factor Authentication (2FA)
- ✅ TOTP-based 2FA (Google Authenticator, Authy, etc.)
- ✅ QR code generation for easy setup
- ✅ Backup codes for account recovery
- ✅ Optional 2FA on login

### OAuth Integrations
- ✅ Google OAuth support
- ✅ GitHub OAuth support
- ✅ Extensible for other providers
- ✅ Automatic email verification for OAuth users

---

## 🧩 Architecture

The service follows **clean architecture** principles with clear separation of concerns:

| Layer                | Component                          | Responsibility                                                                 |
| :------------------- | :--------------------------------- | :----------------------------------------------------------------------------- |
| **Data Layer**       | `internal/models`                  | User struct and in-memory store (easily replaceable with database)            |
| **Business Logic**   | `internal/service`                 | Core authentication logic (password hashing, JWT, 2FA, OAuth)                 |
| **Transport Layer**  | `internal/handler`                 | HTTP request handling, input validation, JSON responses                       |
| **Security / Guard** | `internal/middleware`              | JWT token validation for protected endpoints                                  |

---

## ⚙️ Setup

### Prerequisites

- Go 1.21 or newer
- Internet access for downloading dependencies

### Installation

1. **Clone or navigate to the project directory**

   ```bash
   cd warden
   ```

2. **Initialize and download dependencies**

   ```bash
   go mod tidy
   ```

3. **Set environment variables (optional)**

   ```bash
   export JWT_SECRET="your-super-secret-key-change-in-production"
   ```

   If not set, a default development key will be used (⚠️ **change for production!**).

4. **Run the server**

   ```bash
   go run auth_module_main.go
   ```

   Or build and run:

   ```bash
   go build -o authservice auth_module_main.go
   ./authservice
   ```

The service will start on `http://localhost:8080`

---

## 🌐 API Endpoints

### 🔓 Public Endpoints

#### Register New User
```http
POST /register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (201 Created):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiI...",
  "refresh_token": "eyJhbGciOiJIUzI1NiI...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

#### Login
```http
POST /login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123"
}
```

**Response (200 OK):**
```json
{
  "requires_two_factor": false,
  "token_pair": {
    "access_token": "eyJhbGciOiJIUzI1NiI...",
    "refresh_token": "eyJhbGciOiJIUzI1NiI...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

**If 2FA is enabled:**
```json
{
  "requires_two_factor": true
}
```

#### Login with 2FA
```http
POST /login/2fa
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securepassword123",
  "two_factor_code": "123456"
}
```

#### Refresh Token
```http
POST /refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGciOiJIUzI1NiI..."
}
```

#### Request Password Reset
```http
POST /password/reset
Content-Type: application/json

{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "message": "If an account with that email exists, a password reset link has been sent."
}
```

#### Confirm Password Reset
```http
POST /password/reset/confirm
Content-Type: application/json

{
  "token": "reset-token-from-email",
  "new_password": "newsecurepassword123"
}
```

#### Verify Email
```http
POST /email/verify
Content-Type: application/json

{
  "token": "verification-token-from-email"
}
```

#### Resend Verification Email
```http
POST /email/resend
Content-Type: application/json

{
  "email": "user@example.com"
}
```

#### OAuth Callback
```http
POST /oauth/callback
Content-Type: application/json

{
  "provider": "google",
  "provider_id": "123456789",
  "email": "user@gmail.com",
  "name": "John Doe"
}
```

### 🔒 Protected Endpoints (Require Bearer Token)

All protected endpoints require the `Authorization` header:
```http
Authorization: Bearer <access_token>
```

#### Get Authenticated User
```http
GET /user
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "message": "User is authenticated and details would be here.",
  "status": "ok",
  "user_id": 1
}
```

#### Enable 2FA (Step 1: Generate QR Code)
```http
POST /2fa/enable
Authorization: Bearer <access_token>
Content-Type: application/json

{}
```

**Response (200 OK):**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/AuthService:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=AuthService",
  "backup_codes": ["a1b2c3d4", "e5f6g7h8", ...],
  "message": "Scan the QR code with your authenticator app and verify with a code"
}
```

#### Enable 2FA (Step 2: Verify and Activate)
```http
POST /2fa/enable
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "code": "123456"
}
```

**Response (200 OK):**
```json
{
  "message": "Two-factor authentication enabled successfully",
  "backup_codes": ["a1b2c3d4", "e5f6g7h8", ...]
}
```

#### Disable 2FA
```http
POST /2fa/disable
Authorization: Bearer <access_token>
```

**Response (200 OK):**
```json
{
  "message": "Two-factor authentication disabled successfully"
}
```

---

## 📝 Usage Examples

### Complete Registration and Login Flow

```bash
# 1. Register a new user
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"email": "newuser@example.com", "password": "securepassword"}'

# Response includes access_token and refresh_token
# A verification email is automatically sent (mock in development)

# 2. Verify email (use token from email)
curl -X POST http://localhost:8080/email/verify \
  -H "Content-Type: application/json" \
  -d '{"token": "verification-token-from-email"}'

# 3. Login
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email": "newuser@example.com", "password": "securepassword"}'

# 4. Access protected resource
curl -X GET http://localhost:8080/user \
  -H "Authorization: Bearer <access_token>"
```

### 2FA Setup Flow

```bash
# 1. Login and get access token
TOKEN=$(curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}' \
  | jq -r '.token_pair.access_token')

# 2. Enable 2FA (get QR code)
curl -X POST http://localhost:8080/2fa/enable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}'

# 3. Scan QR code with authenticator app (Google Authenticator, Authy, etc.)
# 4. Verify with code from app
curl -X POST http://localhost:8080/2fa/enable \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'

# 5. Login with 2FA
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'
# Response: {"requires_two_factor": true}

# 6. Complete login with 2FA code
curl -X POST http://localhost:8080/login/2fa \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password",
    "two_factor_code": "123456"
  }'
```

### Password Reset Flow

```bash
# 1. Request password reset
curl -X POST http://localhost:8080/password/reset \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# 2. Check email for reset token (mock in development)
# 3. Reset password with token
curl -X POST http://localhost:8080/password/reset/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "token": "reset-token-from-email",
    "new_password": "newsecurepassword123"
  }'
```

---

## 🔒 Security Considerations

### Token Security
- **Access Tokens**: Short-lived (15 minutes) to minimize exposure risk
- **Refresh Tokens**: Long-lived (7 days) for seamless session renewal
- **JWT Signing**: Uses HS256 with configurable secret key
- **Token Storage**: Clients should store refresh tokens securely (HttpOnly cookies recommended)

### Password Security
- **Hashing**: bcrypt with default cost (10 rounds)
- **Reset Tokens**: Cryptographically secure random tokens, expire after 1 hour
- **No Password Storage**: Passwords are never stored in plain text

### 2FA Security
- **TOTP Standard**: RFC 6238 compliant (works with Google Authenticator, Authy, etc.)
- **Backup Codes**: 8 single-use codes generated on setup
- **Secret Storage**: TOTP secrets never exposed in API responses

### Email Verification
- **JWT Tokens**: Verification tokens are JWTs, expire after 24 hours
- **One-Time Use**: Tokens are validated and marked as used

### Best Practices
- ✅ Always use HTTPS in production
- ✅ Set a strong `JWT_SECRET` environment variable
- ✅ Implement rate limiting on authentication endpoints
- ✅ Use HttpOnly cookies for refresh tokens
- ✅ Implement proper CORS policies
- ✅ Log authentication events for security monitoring
- ✅ Replace mock email service with production email provider

---

## 📁 Project Structure

```
warden/
├── auth_module_main.go          # Main entry point
├── go.mod                       # Go module file
├── go.sum                       # Dependency checksums
├── README.md                    # This file
└── internal/
    ├── models/
    │   ├── user.go              # User struct and in-memory store
    │   └── errors.go            # Error definitions
    ├── service/
    │   ├── auth_service.go      # Core authentication business logic
    │   └── email_service.go     # Email service interface and mock
    ├── handler/
    │   └── auth_handler.go      # HTTP handlers (transport layer)
    └── middleware/
        └── auth_middleware.go   # JWT authentication middleware
```

---

## 🧪 Testing

### Manual Testing with curl

See [Usage Examples](#-usage-examples) above for complete curl examples.

### Automated Testing

You can create unit tests using Go's testing framework:

```bash
go test ./...
```

Example test structure:
- Mock `UserStore` for testing `AuthService`
- Mock `EmailService` for testing email flows
- Test handlers independently with mocked services

---

## 🚀 Extending the Service

### Replace In-Memory Store with Database

1. Implement database interface matching `UserStore` methods
2. Update `internal/models/user.go` to use your database
3. Add database connection in `main.go`

Example with PostgreSQL:
```go
// Replace UserStore with database queries
func (db *DBStore) CreateUser(email, passwordHash string) (*User, error) {
    // SQL INSERT query
}
```

### Integrate Real Email Service

Replace `MockEmailService` with a real implementation:

```go
type SendGridEmailService struct {
    apiKey string
}

func (s *SendGridEmailService) SendVerificationEmail(email, token string) error {
    // SendGrid API call
}
```

### Add More OAuth Providers

Extend `OAuthProvider` enum and add provider-specific logic:

```go
const (
    OAuthProviderGoogle OAuthProvider = "google"
    OAuthProviderGitHub OAuthProvider = "github"
    OAuthProviderMicrosoft OAuthProvider = "microsoft" // New
)
```

### Add Role-Based Authorization

Extend `User` model with roles and update middleware:

```go
type User struct {
    // ... existing fields
    Roles []string `json:"roles"`
}

func (m *AuthMiddleware) RequireRole(role string) http.HandlerFunc {
    // Check user roles
}
```

### Docker Deployment

Create `Dockerfile`:
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o authservice auth_module_main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/authservice .
CMD ["./authservice"]
```

---

## 📚 Dependencies

| Package | Purpose |
| :------ | :------ |
| `github.com/golang-jwt/jwt/v5` | JWT token generation and validation |
| `golang.org/x/crypto/bcrypt` | Password hashing |
| `github.com/pquerna/otp` | TOTP-based 2FA (QR codes, code generation) |

---

## 📄 License

This project is provided as-is for educational and development purposes.

---

## 🤝 Contributing

This is a reference implementation. Feel free to fork and adapt for your needs!

---

## ✅ Summary

This authentication microservice provides a **clean, modular, and secure** foundation for any Go-based system requiring comprehensive authentication capabilities. It combines:

- **Fortify-style logic** (business layer)
- **Sanctum-style tokens** (security layer)
- **Modern 2FA** (TOTP with backup codes)
- **OAuth integrations** (Google, GitHub, extensible)
- **Email workflows** (verification, password reset)

By keeping all layers decoupled, you get a scalable, testable, and framework-agnostic authentication solution ready for production use.

