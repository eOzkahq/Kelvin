package auth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresRepository implements Repository using PostgreSQL via pgxpool.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository instantiates a new PostgreSQL auth repository.
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if r.pool == nil {
		return nil, errors.New("database pool is not configured")
	}

	query := `
		SELECT u.id, u.tenant_id, u.email, u.display_name, u.password_hash, u.role, u.is_active,
		       u.last_login_at, u.created_at, u.updated_at,
		       t.name, t.slug, t.status
		FROM users u
		JOIN tenants t ON u.tenant_id = t.id
		WHERE lower(u.email) = lower($1)
		  AND u.deleted_at IS NULL
		  AND t.deleted_at IS NULL
		LIMIT 1;
	`

	var u User
	var roleStr, tenantStatus string
	var lastLoginAt *time.Time

	err := r.pool.QueryRow(ctx, query, email).Scan(
		&u.ID,
		&u.TenantID,
		&u.Email,
		&u.DisplayName,
		&u.PasswordHash,
		&roleStr,
		&u.IsActive,
		&lastLoginAt,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.TenantName,
		&u.TenantSlug,
		&tenantStatus,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to query user by email: %w", err)
	}

	u.Role = Role(roleStr)
	u.LastLoginAt = lastLoginAt

	if !u.IsActive {
		return nil, ErrUserInactive
	}
	if tenantStatus != "ACTIVE" {
		return nil, ErrTenantInactive
	}

	return &u, nil
}

func (r *PostgresRepository) GetUserByID(ctx context.Context, tenantID, userID uuid.UUID) (*User, error) {
	if r.pool == nil {
		return nil, errors.New("database pool is not configured")
	}

	query := `
		SELECT u.id, u.tenant_id, u.email, u.display_name, u.password_hash, u.role, u.is_active,
		       u.last_login_at, u.created_at, u.updated_at,
		       t.name, t.slug, t.status
		FROM users u
		JOIN tenants t ON u.tenant_id = t.id
		WHERE u.tenant_id = $1 AND u.id = $2
		  AND u.deleted_at IS NULL
		  AND t.deleted_at IS NULL
		LIMIT 1;
	`

	var u User
	var roleStr, tenantStatus string
	var lastLoginAt *time.Time

	err := r.pool.QueryRow(ctx, query, tenantID, userID).Scan(
		&u.ID,
		&u.TenantID,
		&u.Email,
		&u.DisplayName,
		&u.PasswordHash,
		&roleStr,
		&u.IsActive,
		&lastLoginAt,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.TenantName,
		&u.TenantSlug,
		&tenantStatus,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to query user by ID: %w", err)
	}

	u.Role = Role(roleStr)
	u.LastLoginAt = lastLoginAt

	if !u.IsActive {
		return nil, ErrUserInactive
	}
	if tenantStatus != "ACTIVE" {
		return nil, ErrTenantInactive
	}

	return &u, nil
}

func (r *PostgresRepository) UpdateUserLastLogin(ctx context.Context, userID uuid.UUID) error {
	if r.pool == nil {
		return errors.New("database pool is not configured")
	}

	query := `UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`
	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to update user last login: %w", err)
	}
	return nil
}

func (r *PostgresRepository) CreateSession(ctx context.Context, s *Session) error {
	if r.pool == nil {
		return errors.New("database pool is not configured")
	}

	query := `
		INSERT INTO auth_sessions (
			id, tenant_id, user_id, token_family, token_hash,
			issued_at, last_used_at, expires_at, revoked_at,
			user_agent, ip_address, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13
		);
	`

	var ipArg *string
	if s.IPAddress != "" {
		if parsedIP := net.ParseIP(s.IPAddress); parsedIP != nil {
			cleanIP := parsedIP.String()
			ipArg = &cleanIP
		}
	}

	now := time.Now().UTC()
	if s.IssuedAt.IsZero() {
		s.IssuedAt = now
	}
	if s.LastUsedAt.IsZero() {
		s.LastUsedAt = now
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	if s.UpdatedAt.IsZero() {
		s.UpdatedAt = now
	}

	_, err := r.pool.Exec(ctx, query,
		s.ID, s.TenantID, s.UserID, s.TokenFamily, s.TokenHash,
		s.IssuedAt, s.LastUsedAt, s.ExpiresAt, s.RevokedAt,
		s.UserAgent, ipArg, s.CreatedAt, s.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to insert auth session: %w", err)
	}
	return nil
}

func (r *PostgresRepository) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	if r.pool == nil {
		return nil, errors.New("database pool is not configured")
	}

	query := `
		SELECT id, tenant_id, user_id, token_family, token_hash,
		       issued_at, last_used_at, expires_at, revoked_at,
		       COALESCE(user_agent, ''), COALESCE(host(ip_address), ''), created_at, updated_at
		FROM auth_sessions
		WHERE token_hash = $1
		LIMIT 1;
	`

	var s Session
	var userAgent, ipAddr string
	var revokedAt *time.Time

	err := r.pool.QueryRow(ctx, query, tokenHash).Scan(
		&s.ID,
		&s.TenantID,
		&s.UserID,
		&s.TokenFamily,
		&s.TokenHash,
		&s.IssuedAt,
		&s.LastUsedAt,
		&s.ExpiresAt,
		&revokedAt,
		&userAgent,
		&ipAddr,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("failed to query auth session: %w", err)
	}

	s.RevokedAt = revokedAt
	s.UserAgent = userAgent
	s.IPAddress = ipAddr

	return &s, nil
}

func (r *PostgresRepository) RotateSession(ctx context.Context, oldSessionID uuid.UUID, newSession *Session) error {
	if r.pool == nil {
		return errors.New("database pool is not configured")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Revoke old session
	revokeQuery := `UPDATE auth_sessions SET revoked_at = now(), updated_at = now() WHERE id = $1`
	if _, err := tx.Exec(ctx, revokeQuery, oldSessionID); err != nil {
		return fmt.Errorf("failed to revoke old session: %w", err)
	}

	// Insert new session
	insertQuery := `
		INSERT INTO auth_sessions (
			id, tenant_id, user_id, token_family, token_hash,
			issued_at, last_used_at, expires_at, revoked_at,
			user_agent, ip_address, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13
		);
	`

	var ipArg *string
	if newSession.IPAddress != "" {
		if parsedIP := net.ParseIP(newSession.IPAddress); parsedIP != nil {
			cleanIP := parsedIP.String()
			ipArg = &cleanIP
		}
	}

	now := time.Now().UTC()
	if newSession.IssuedAt.IsZero() {
		newSession.IssuedAt = now
	}
	if newSession.LastUsedAt.IsZero() {
		newSession.LastUsedAt = now
	}
	if newSession.CreatedAt.IsZero() {
		newSession.CreatedAt = now
	}
	if newSession.UpdatedAt.IsZero() {
		newSession.UpdatedAt = now
	}

	if _, err := tx.Exec(ctx, insertQuery,
		newSession.ID, newSession.TenantID, newSession.UserID, newSession.TokenFamily, newSession.TokenHash,
		newSession.IssuedAt, newSession.LastUsedAt, newSession.ExpiresAt, newSession.RevokedAt,
		newSession.UserAgent, ipArg, newSession.CreatedAt, newSession.UpdatedAt,
	); err != nil {
		return fmt.Errorf("failed to insert new session in rotation: %w", err)
	}

	return tx.Commit(ctx)
}

func (r *PostgresRepository) RevokeSession(ctx context.Context, sessionID uuid.UUID) error {
	if r.pool == nil {
		return errors.New("database pool is not configured")
	}

	query := `UPDATE auth_sessions SET revoked_at = now(), updated_at = now() WHERE id = $1 AND revoked_at IS NULL`
	_, err := r.pool.Exec(ctx, query, sessionID)
	if err != nil {
		return fmt.Errorf("failed to revoke auth session: %w", err)
	}
	return nil
}

func (r *PostgresRepository) RevokeSessionFamily(ctx context.Context, familyID uuid.UUID) error {
	if r.pool == nil {
		return errors.New("database pool is not configured")
	}

	query := `UPDATE auth_sessions SET revoked_at = now(), updated_at = now() WHERE token_family = $1 AND revoked_at IS NULL`
	_, err := r.pool.Exec(ctx, query, familyID)
	if err != nil {
		return fmt.Errorf("failed to revoke auth session family: %w", err)
	}
	return nil
}

func (r *PostgresRepository) GetTenantByID(ctx context.Context, tenantID uuid.UUID) (*Tenant, error) {
	if r.pool == nil {
		return nil, errors.New("database pool is not configured")
	}

	query := `SELECT id, name, slug, status, created_at, updated_at FROM tenants WHERE id = $1 AND deleted_at IS NULL LIMIT 1;`
	var t Tenant
	err := r.pool.QueryRow(ctx, query, tenantID).Scan(
		&t.ID,
		&t.Name,
		&t.Slug,
		&t.Status,
		&t.CreatedAt,
		&t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("failed to query tenant by ID: %w", err)
	}
	return &t, nil
}

func (r *PostgresRepository) CreateTenantAndAdmin(ctx context.Context, tenant *Tenant, admin *User) error {
	if r.pool == nil {
		return errors.New("database pool is not configured")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 1. Insert or update tenant
	tenantQuery := `
		INSERT INTO tenants (id, name, slug, status, settings, created_at, updated_at)
		VALUES ($1, $2, $3, 'ACTIVE', '{}'::jsonb, now(), now())
		ON CONFLICT (slug) DO UPDATE
		SET name = EXCLUDED.name, status = 'ACTIVE', updated_at = now()
		RETURNING id;
	`
	var actualTenantID uuid.UUID
	err = tx.QueryRow(ctx, tenantQuery, tenant.ID, tenant.Name, tenant.Slug).Scan(&actualTenantID)
	if err != nil {
		return fmt.Errorf("failed to upsert tenant: %w", err)
	}
	tenant.ID = actualTenantID
	admin.TenantID = actualTenantID

	// 2. Insert or update admin user
	userQuery := `
		INSERT INTO users (id, tenant_id, email, display_name, password_hash, role, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, true, now(), now())
		ON CONFLICT (tenant_id, lower(email)) WHERE deleted_at IS NULL
		DO UPDATE SET password_hash = EXCLUDED.password_hash,
		              display_name = EXCLUDED.display_name,
		              role = EXCLUDED.role,
		              is_active = true,
		              updated_at = now()
		RETURNING id;
	`
	var actualUserID uuid.UUID
	err = tx.QueryRow(ctx, userQuery,
		admin.ID, admin.TenantID, admin.Email, admin.DisplayName, admin.PasswordHash, string(admin.Role),
	).Scan(&actualUserID)
	if err != nil {
		return fmt.Errorf("failed to upsert admin user: %w", err)
	}
	admin.ID = actualUserID

	return tx.Commit(ctx)
}
