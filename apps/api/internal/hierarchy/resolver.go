package hierarchy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/tenant"
)

var (
	ErrMissingSecurityContext = errors.New("security context is missing from context")
	ErrNoActiveMembership     = errors.New("user has no active organization membership")
	ErrNoWorkspaceAccess      = errors.New("user has no access to requested workspace")
)

// EffectiveSecurityContext represents the verified, tamper-proof security context for an authenticated user.
type EffectiveSecurityContext struct {
	UserID         string        `json:"user_id"`
	OrganizationID uuid.UUID     `json:"organization_id"`
	OrgRole        OrgRole       `json:"org_role"`
	WorkspaceID    uuid.UUID     `json:"workspace_id"`
	WorkspaceRole  WorkspaceRole `json:"workspace_role"`
	TenantID       uuid.UUID     `json:"tenant_id"` // Cryptographically isolated database tenant ID
	TeamIDs        []uuid.UUID   `json:"team_ids"`
	ResolvedAt     time.Time     `json:"resolved_at"`
}

// MembershipCache defines the caching contract for resolved membership contexts.
type MembershipCache interface {
	Get(ctx context.Context, userID string, workspaceID uuid.UUID) (*EffectiveSecurityContext, bool)
	Set(ctx context.Context, sec *EffectiveSecurityContext, ttl time.Duration)
	InvalidateUser(ctx context.Context, userID string)
}

// MemoryMembershipCache provides an in-memory thread-safe implementation of MembershipCache.
type MemoryMembershipCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

type cacheEntry struct {
	context   *EffectiveSecurityContext
	expiresAt time.Time
}

func NewMemoryMembershipCache() *MemoryMembershipCache {
	return &MemoryMembershipCache{
		entries: make(map[string]cacheEntry),
	}
}

func makeCacheKey(userID string, workspaceID uuid.UUID) string {
	return fmt.Sprintf("mem:%s:%s", userID, workspaceID.String())
}

func (c *MemoryMembershipCache) Get(ctx context.Context, userID string, workspaceID uuid.UUID) (*EffectiveSecurityContext, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := makeCacheKey(userID, workspaceID)
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().UTC().After(entry.expiresAt) {
		return nil, false
	}
	return entry.context, true
}

func (c *MemoryMembershipCache) Set(ctx context.Context, sec *EffectiveSecurityContext, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := makeCacheKey(sec.UserID, sec.WorkspaceID)
	c.entries[key] = cacheEntry{
		context:   sec,
		expiresAt: time.Now().UTC().Add(ttl),
	}
}

func (c *MemoryMembershipCache) InvalidateUser(ctx context.Context, userID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prefix := fmt.Sprintf("mem:%s:", userID)
	for key := range c.entries {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(c.entries, key)
		}
	}
}

// Context attachment
type securityContextKey struct{}

// WithSecurityContext attaches the resolved EffectiveSecurityContext to context.Context,
// also injecting the underlying TenantID into packages/common/tenant.
func WithSecurityContext(ctx context.Context, sec *EffectiveSecurityContext) (context.Context, error) {
	ctxWithTenant, err := tenant.WithID(ctx, sec.TenantID)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctxWithTenant, securityContextKey{}, sec), nil
}

// SecurityContextFromContext extracts the EffectiveSecurityContext from context.Context.
func SecurityContextFromContext(ctx context.Context) (*EffectiveSecurityContext, error) {
	sec, ok := ctx.Value(securityContextKey{}).(*EffectiveSecurityContext)
	if !ok || sec == nil {
		return nil, ErrMissingSecurityContext
	}
	return sec, nil
}

// MembershipResolver coordinates membership and ownership resolution.
type MembershipResolver struct {
	repo  HierarchyRepository
	cache MembershipCache
	ttl   time.Duration
}

func NewMembershipResolver(repo HierarchyRepository, cache MembershipCache, ttl time.Duration) *MembershipResolver {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &MembershipResolver{
		repo:  repo,
		cache: cache,
		ttl:   ttl,
	}
}

// ResolveContext evaluates the trusted server-side security context for a user and optional requested workspace.
func (r *MembershipResolver) ResolveContext(ctx context.Context, userID string, requestedWorkspaceID *uuid.UUID) (*EffectiveSecurityContext, error) {
	// 1. If requestedWorkspaceID provided and cache hit exists, return cached context
	if requestedWorkspaceID != nil && r.cache != nil {
		if cached, ok := r.cache.Get(ctx, userID, *requestedWorkspaceID); ok {
			return cached, nil
		}
	}

	// 2. Discover user's workspaces and organization
	var targetWS *Workspace
	if requestedWorkspaceID != nil {
		ws, err := r.repo.GetWorkspace(ctx, *requestedWorkspaceID)
		if err != nil {
			return nil, ErrWorkspaceNotFound
		}
		targetWS = ws
	}

	// 3. If targetWS is set, verify user has membership in its parent organization
	var orgID uuid.UUID
	var orgRole OrgRole
	if targetWS != nil {
		orgID = targetWS.OrganizationID
		mem, err := r.repo.GetOrgMembership(ctx, orgID, userID)
		if err != nil {
			return nil, ErrUnauthorized
		}
		orgRole = mem.Role
	} else {
		// If no workspace requested, find user's default workspace
		// Look up all workspaces to find accessible one
		return nil, ErrWorkspaceNotFound
	}

	// 4. Verify organization is ACTIVE
	org, err := r.repo.GetOrganization(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if org.Status != OrgStateActive {
		return nil, ErrOrgSuspended
	}

	// 5. Resolve effective workspace role
	var bestRole WorkspaceRole
	hasRole := false

	// Check direct membership
	if wsMem, err := r.repo.GetWorkspaceMembership(ctx, targetWS.ID, userID); err == nil {
		bestRole = wsMem.Role
		hasRole = true
	}

	// Check team grants
	teams, err := r.repo.GetUserTeams(ctx, orgID, userID)
	var teamIDs []uuid.UUID
	if err == nil {
		for _, t := range teams {
			teamIDs = append(teamIDs, t.ID)
			if grant, err := r.repo.GetTeamWorkspaceGrant(ctx, targetWS.ID, t.ID); err == nil {
				if !hasRole || isWorkspaceRoleSufficient(grant.Role, bestRole) {
					bestRole = grant.Role
					hasRole = true
				}
			}
		}
	}

	// Org Owner / Admin fallback if granted workspace administration
	if !hasRole && (orgRole == OrgRoleOwner || orgRole == OrgRoleAdmin) {
		// Org admins have ADMIN role on workspaces within their organization
		bestRole = WorkspaceRoleAdmin
		hasRole = true
	}

	if !hasRole {
		return nil, ErrNoWorkspaceAccess
	}

	sec := &EffectiveSecurityContext{
		UserID:         userID,
		OrganizationID: orgID,
		OrgRole:        orgRole,
		WorkspaceID:    targetWS.ID,
		WorkspaceRole:  bestRole,
		TenantID:       targetWS.TenantID,
		TeamIDs:        teamIDs,
		ResolvedAt:     time.Now().UTC(),
	}

	if r.cache != nil {
		r.cache.Set(ctx, sec, r.ttl)
	}

	return sec, nil
}
