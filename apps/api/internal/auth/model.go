package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidPassword = errors.New("invalid password")
	ErrUserInactive    = errors.New("user account is inactive")
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionRevoked  = errors.New("session has been revoked")
	ErrSessionExpired  = errors.New("session has expired")
	ErrTenantNotFound  = errors.New("tenant not found")
	ErrTenantInactive  = errors.New("tenant is inactive")
)

// User represents an authenticated identity within a tenant.
type User struct {
	ID           uuid.UUID  `json:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"`
	Email        string     `json:"email"`
	DisplayName  string     `json:"name"`
	PasswordHash string     `json:"-"`
	Role         Role       `json:"role"`
	IsActive     bool       `json:"is_active"`
	TenantName   string     `json:"organization_name,omitempty"`
	TenantSlug   string     `json:"organization_slug,omitempty"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Tenant represents an organization boundary.
type Tenant struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Session represents an active refresh session in auth_sessions.
type Session struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	UserID      uuid.UUID  `json:"user_id"`
	TokenFamily uuid.UUID  `json:"token_family"`
	TokenHash   string     `json:"-"`
	IssuedAt    time.Time  `json:"issued_at"`
	LastUsedAt  time.Time  `json:"last_used_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	UserAgent   string     `json:"user_agent,omitempty"`
	IPAddress   string     `json:"ip_address,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Repository defines data access methods for authentication entities.
type Repository interface {
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, tenantID, userID uuid.UUID) (*User, error)
	UpdateUserLastLogin(ctx context.Context, userID uuid.UUID) error
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	RotateSession(ctx context.Context, oldSessionID uuid.UUID, newSession *Session) error
	RevokeSession(ctx context.Context, sessionID uuid.UUID) error
	RevokeSessionFamily(ctx context.Context, familyID uuid.UUID) error
	GetTenantByID(ctx context.Context, tenantID uuid.UUID) (*Tenant, error)
	CreateTenantAndAdmin(ctx context.Context, tenant *Tenant, admin *User) error
}
