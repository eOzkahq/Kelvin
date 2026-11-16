package auth

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryRepository provides an in-memory implementation of Repository for unit testing.
type MemoryRepository struct {
	mu       sync.RWMutex
	tenants  map[uuid.UUID]*Tenant
	users    map[uuid.UUID]*User
	sessions map[uuid.UUID]*Session
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		tenants:  make(map[uuid.UUID]*Tenant),
		users:    make(map[uuid.UUID]*User),
		sessions: make(map[uuid.UUID]*Session),
	}
}

func (m *MemoryRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	normEmail := strings.ToLower(strings.TrimSpace(email))
	for _, u := range m.users {
		if strings.ToLower(u.Email) == normEmail {
			t, ok := m.tenants[u.TenantID]
			if !ok || t.Status != "ACTIVE" {
				return nil, ErrTenantInactive
			}
			if !u.IsActive {
				return nil, ErrUserInactive
			}
			copyUser := *u
			copyUser.TenantName = t.Name
			copyUser.TenantSlug = t.Slug
			return &copyUser, nil
		}
	}
	return nil, ErrUserNotFound
}

func (m *MemoryRepository) GetUserByID(ctx context.Context, tenantID, userID uuid.UUID) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	u, ok := m.users[userID]
	if !ok || u.TenantID != tenantID {
		return nil, ErrUserNotFound
	}
	t, ok := m.tenants[u.TenantID]
	if !ok || t.Status != "ACTIVE" {
		return nil, ErrTenantInactive
	}
	if !u.IsActive {
		return nil, ErrUserInactive
	}
	copyUser := *u
	copyUser.TenantName = t.Name
	copyUser.TenantSlug = t.Slug
	return &copyUser, nil
}

func (m *MemoryRepository) UpdateUserLastLogin(ctx context.Context, userID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.users[userID]
	if !ok {
		return ErrUserNotFound
	}
	now := time.Now().UTC()
	u.LastLoginAt = &now
	u.UpdatedAt = now
	return nil
}

func (m *MemoryRepository) CreateSession(ctx context.Context, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	copySession := *session
	m.sessions[session.ID] = &copySession
	return nil
}

func (m *MemoryRepository) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, s := range m.sessions {
		if s.TokenHash == tokenHash {
			copySession := *s
			return &copySession, nil
		}
	}
	return nil, ErrSessionNotFound
}

func (m *MemoryRepository) RotateSession(ctx context.Context, oldSessionID uuid.UUID, newSession *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	old, ok := m.sessions[oldSessionID]
	if !ok {
		return ErrSessionNotFound
	}
	now := time.Now().UTC()
	old.RevokedAt = &now
	old.UpdatedAt = now

	copyNew := *newSession
	m.sessions[newSession.ID] = &copyNew
	return nil
}

func (m *MemoryRepository) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[sessionID]
	if !ok {
		return nil
	}
	if s.RevokedAt == nil {
		now := time.Now().UTC()
		s.RevokedAt = &now
		s.UpdatedAt = now
	}
	return nil
}

func (m *MemoryRepository) RevokeSessionFamily(ctx context.Context, familyID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	for _, s := range m.sessions {
		if s.TokenFamily == familyID && s.RevokedAt == nil {
			s.RevokedAt = &now
			s.UpdatedAt = now
		}
	}
	return nil
}

func (m *MemoryRepository) GetTenantByID(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	t, ok := m.tenants[tenantID]
	if !ok {
		return nil, ErrTenantNotFound
	}
	copyTenant := *t
	return &copyTenant, nil
}

func (m *MemoryRepository) CreateTenantAndAdmin(ctx context.Context, tenant *Tenant, admin *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = now
	}
	tenant.UpdatedAt = now
	tenant.Status = "ACTIVE"
	m.tenants[tenant.ID] = tenant

	admin.TenantID = tenant.ID
	if admin.CreatedAt.IsZero() {
		admin.CreatedAt = now
	}
	admin.UpdatedAt = now
	admin.IsActive = true
	m.users[admin.ID] = admin
	return nil
}
