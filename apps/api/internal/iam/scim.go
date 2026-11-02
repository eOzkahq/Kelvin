package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

const (
	SCIMUserSchema         = "urn:ietf:params:scim:schemas:core:2.0:User"
	SCIMGroupSchema        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	SCIMListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	SCIMErrorSchema        = "urn:ietf:params:scim:api:messages:2.0:Error"
	SCIMPatchOpSchema      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

var (
	ErrSCIMUnauthorized             = errors.New("SCIM request unauthorized: invalid or expired bearer token")
	ErrSCIMConflict                 = errors.New("SCIM uniqueness conflict: user or group already exists")
	ErrSCIMNotFound                 = errors.New("SCIM resource not found")
	ErrSCIMPrivilegedGroupForbidden = errors.New("SCIM group synchronization cannot grant platform-level privileged roles")
)

const (
	ActionSCIMTokenCreated     = "scim.token_created"
	ActionSCIMUserCreated      = "scim.user.created"
	ActionSCIMUserUpdated      = "scim.user.updated"
	ActionSCIMUserDeactivated  = "scim.user.deactivated"
	ActionSCIMGroupCreated     = "scim.group.created"
	ActionSCIMGroupUpdated     = "scim.group.updated"
)

// SCIMMeta describes RFC 7643 resource metadata.
type SCIMMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
}

// SCIMName represents an individual's name components.
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// SCIMEmail represents an email entry.
type SCIMEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// SCIMUser represents a SCIM 2.0 User resource (RFC 7643).
type SCIMUser struct {
	Schemas    []string    `json:"schemas"`
	ID         string      `json:"id"`
	ExternalID string      `json:"externalId,omitempty"`
	UserName   string      `json:"userName"`
	Name       SCIMName    `json:"name,omitempty"`
	Emails     []SCIMEmail `json:"emails,omitempty"`
	Active     bool        `json:"active"`
	Meta       SCIMMeta    `json:"meta"`
}

// SCIMMember represents a group member reference.
type SCIMMember struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Type    string `json:"type,omitempty"`
}

// SCIMGroup represents a SCIM 2.0 Group resource (RFC 7643).
type SCIMGroup struct {
	Schemas     []string     `json:"schemas"`
	ID          string       `json:"id"`
	DisplayName string       `json:"displayName"`
	ExternalID  string       `json:"externalId,omitempty"`
	Members     []SCIMMember `json:"members"`
	Meta        SCIMMeta     `json:"meta"`
}

// SCIMListResponse defines standard RFC 7644 collection response.
type SCIMListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// SCIMPatchOp represents an individual patch operation.
type SCIMPatchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value"`
}

// SCIMPatchRequest represents a SCIM 2.0 Patch payload.
type SCIMPatchRequest struct {
	Schemas    []string      `json:"schemas"`
	Operations []SCIMPatchOp `json:"Operations"`
}

// SCIMToken records an organization's provisioned SCIM bearer token.
type SCIMToken struct {
	ID             uuid.UUID  `json:"id"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	TokenHash      string     `json:"token_hash"`
	Description    string     `json:"description"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// SCIMRepository defines persistence operations for SCIM tokens, users, and groups.
type SCIMRepository interface {
	SaveToken(ctx context.Context, token *SCIMToken) error
	GetTokenByHash(ctx context.Context, hash string) (*SCIMToken, error)

	SaveUser(ctx context.Context, orgID uuid.UUID, user *SCIMUser) error
	GetUser(ctx context.Context, orgID uuid.UUID, id string) (*SCIMUser, error)
	GetUserByUserName(ctx context.Context, orgID uuid.UUID, userName string) (*SCIMUser, error)
	GetUserByExternalID(ctx context.Context, orgID uuid.UUID, extID string) (*SCIMUser, error)
	UpdateUser(ctx context.Context, orgID uuid.UUID, user *SCIMUser) error
	ListUsers(ctx context.Context, orgID uuid.UUID, startIndex, count int) ([]*SCIMUser, int, error)

	SaveGroup(ctx context.Context, orgID uuid.UUID, group *SCIMGroup) error
	GetGroup(ctx context.Context, orgID uuid.UUID, id string) (*SCIMGroup, error)
	GetGroupByDisplayName(ctx context.Context, orgID uuid.UUID, name string) (*SCIMGroup, error)
	UpdateGroup(ctx context.Context, orgID uuid.UUID, group *SCIMGroup) error
	ListGroups(ctx context.Context, orgID uuid.UUID, startIndex, count int) ([]*SCIMGroup, int, error)
}

// MemorySCIMRepository provides an in-memory implementation of SCIMRepository.
type MemorySCIMRepository struct {
	mu     sync.RWMutex
	tokens map[string]*SCIMToken
	users  map[string]*SCIMUser  // key: orgID:userID
	groups map[string]*SCIMGroup // key: orgID:groupID
}

func NewMemorySCIMRepository() *MemorySCIMRepository {
	return &MemorySCIMRepository{
		tokens: make(map[string]*SCIMToken),
		users:  make(map[string]*SCIMUser),
		groups: make(map[string]*SCIMGroup),
	}
}

func (m *MemorySCIMRepository) SaveToken(ctx context.Context, token *SCIMToken) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[token.TokenHash] = token
	return nil
}

func (m *MemorySCIMRepository) GetTokenByHash(ctx context.Context, hash string) (*SCIMToken, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tok, ok := m.tokens[hash]
	if !ok {
		return nil, ErrSCIMUnauthorized
	}
	return tok, nil
}

func (m *MemorySCIMRepository) SaveUser(ctx context.Context, orgID uuid.UUID, user *SCIMUser) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID.String() + ":" + user.ID
	m.users[key] = user
	return nil
}

func (m *MemorySCIMRepository) GetUser(ctx context.Context, orgID uuid.UUID, id string) (*SCIMUser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := orgID.String() + ":" + id
	user, ok := m.users[key]
	if !ok {
		return nil, ErrSCIMNotFound
	}
	return user, nil
}

func (m *MemorySCIMRepository) GetUserByUserName(ctx context.Context, orgID uuid.UUID, userName string) (*SCIMUser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := orgID.String() + ":"
	norm := strings.ToLower(userName)
	for k, u := range m.users {
		if strings.HasPrefix(k, prefix) && strings.ToLower(u.UserName) == norm {
			return u, nil
		}
	}
	return nil, ErrSCIMNotFound
}

func (m *MemorySCIMRepository) GetUserByExternalID(ctx context.Context, orgID uuid.UUID, extID string) (*SCIMUser, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := orgID.String() + ":"
	for k, u := range m.users {
		if strings.HasPrefix(k, prefix) && u.ExternalID == extID {
			return u, nil
		}
	}
	return nil, ErrSCIMNotFound
}

func (m *MemorySCIMRepository) UpdateUser(ctx context.Context, orgID uuid.UUID, user *SCIMUser) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID.String() + ":" + user.ID
	if _, ok := m.users[key]; !ok {
		return ErrSCIMNotFound
	}
	m.users[key] = user
	return nil
}

func (m *MemorySCIMRepository) ListUsers(ctx context.Context, orgID uuid.UUID, startIndex, count int) ([]*SCIMUser, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := orgID.String() + ":"
	var matched []*SCIMUser
	for k, u := range m.users {
		if strings.HasPrefix(k, prefix) {
			matched = append(matched, u)
		}
	}
	total := len(matched)
	if startIndex <= 0 {
		startIndex = 1
	}
	if count <= 0 {
		count = 50
	}
	start := startIndex - 1
	if start >= total {
		return []*SCIMUser{}, total, nil
	}
	end := start + count
	if end > total {
		end = total
	}
	return matched[start:end], total, nil
}

func (m *MemorySCIMRepository) SaveGroup(ctx context.Context, orgID uuid.UUID, group *SCIMGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID.String() + ":" + group.ID
	m.groups[key] = group
	return nil
}

func (m *MemorySCIMRepository) GetGroup(ctx context.Context, orgID uuid.UUID, id string) (*SCIMGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := orgID.String() + ":" + id
	g, ok := m.groups[key]
	if !ok {
		return nil, ErrSCIMNotFound
	}
	return g, nil
}

func (m *MemorySCIMRepository) GetGroupByDisplayName(ctx context.Context, orgID uuid.UUID, name string) (*SCIMGroup, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := orgID.String() + ":"
	norm := strings.ToLower(name)
	for k, g := range m.groups {
		if strings.HasPrefix(k, prefix) && strings.ToLower(g.DisplayName) == norm {
			return g, nil
		}
	}
	return nil, ErrSCIMNotFound
}

func (m *MemorySCIMRepository) UpdateGroup(ctx context.Context, orgID uuid.UUID, group *SCIMGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := orgID.String() + ":" + group.ID
	if _, ok := m.groups[key]; !ok {
		return ErrSCIMNotFound
	}
	m.groups[key] = group
	return nil
}

func (m *MemorySCIMRepository) ListGroups(ctx context.Context, orgID uuid.UUID, startIndex, count int) ([]*SCIMGroup, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	prefix := orgID.String() + ":"
	var matched []*SCIMGroup
	for k, g := range m.groups {
		if strings.HasPrefix(k, prefix) {
			matched = append(matched, g)
		}
	}
	total := len(matched)
	if startIndex <= 0 {
		startIndex = 1
	}
	if count <= 0 {
		count = 50
	}
	start := startIndex - 1
	if start >= total {
		return []*SCIMGroup{}, total, nil
	}
	end := start + count
	if end > total {
		end = total
	}
	return matched[start:end], total, nil
}

// SCIMService handles RFC 7644 operations and security invariants.
type SCIMService struct {
	repo  SCIMRepository
	audit audit.Recorder
}

func NewSCIMService(repo SCIMRepository, audit audit.Recorder) *SCIMService {
	return &SCIMService{
		repo:  repo,
		audit: audit,
	}
}

// GenerateSCIMToken creates a high-entropy bearer token for IdP provisioning.
func (s *SCIMService) GenerateSCIMToken(ctx context.Context, actorUserID string, orgID uuid.UUID, description string) (rawToken string, token *SCIMToken, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	rawToken = "kelvin_scim_" + hex.EncodeToString(b)
	hash := sha256Hash(rawToken)

	now := time.Now().UTC()
	token = &SCIMToken{
		ID:             uuid.New(),
		OrganizationID: orgID,
		TokenHash:      hash,
		Description:    description,
		CreatedAt:      now,
	}

	if err := s.repo.SaveToken(ctx, token); err != nil {
		return "", nil, err
	}

	s.recordAudit(ctx, orgID, actorUserID, ActionSCIMTokenCreated, token.ID)
	return rawToken, token, nil
}

// AuthenticateToken verifies a SCIM bearer token and returns the bound Organization ID.
func (s *SCIMService) AuthenticateToken(ctx context.Context, rawToken string) (uuid.UUID, error) {
	hash := sha256Hash(rawToken)
	token, err := s.repo.GetTokenByHash(ctx, hash)
	if err != nil {
		return uuid.Nil, ErrSCIMUnauthorized
	}
	if token.RevokedAt != nil {
		return uuid.Nil, ErrSCIMUnauthorized
	}
	if token.ExpiresAt != nil && time.Now().UTC().After(*token.ExpiresAt) {
		return uuid.Nil, ErrSCIMUnauthorized
	}
	return token.OrganizationID, nil
}

// CreateUser creates a SCIM user idempotently or returns 409 Conflict.
func (s *SCIMService) CreateUser(ctx context.Context, orgID uuid.UUID, user *SCIMUser) (*SCIMUser, error) {
	if strings.TrimSpace(user.UserName) == "" {
		return nil, errors.New("userName is required")
	}

	// Idempotency / conflict check
	if existing, err := s.repo.GetUserByUserName(ctx, orgID, user.UserName); err == nil {
		if user.ExternalID != "" && existing.ExternalID == user.ExternalID {
			return existing, nil // Idempotent return
		}
		return nil, ErrSCIMConflict
	}

	now := time.Now().UTC()
	user.ID = uuid.New().String()
	user.Schemas = []string{SCIMUserSchema}
	user.Meta = SCIMMeta{
		ResourceType: "User",
		Created:      now,
		LastModified: now,
	}

	if err := s.repo.SaveUser(ctx, orgID, user); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, orgID, "", ActionSCIMUserCreated, uuid.MustParse(user.ID))
	return user, nil
}

// GetUser fetches a SCIM user by ID within the organization boundary.
func (s *SCIMService) GetUser(ctx context.Context, orgID uuid.UUID, id string) (*SCIMUser, error) {
	return s.repo.GetUser(ctx, orgID, id)
}

// PatchUser applies partial updates (e.g. active=false for deactivation).
func (s *SCIMService) PatchUser(ctx context.Context, orgID uuid.UUID, id string, patch SCIMPatchRequest) (*SCIMUser, error) {
	user, err := s.repo.GetUser(ctx, orgID, id)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	wasActive := user.Active

	for _, op := range patch.Operations {
		opName := strings.ToLower(op.Op)
		path := strings.ToLower(op.Path)

		if opName == "replace" || opName == "add" {
			if path == "active" || path == "" {
				if b, ok := op.Value.(bool); ok {
					user.Active = b
				} else if m, ok := op.Value.(map[string]any); ok {
					if activeVal, hasActive := m["active"]; hasActive {
						if ab, ok := activeVal.(bool); ok {
							user.Active = ab
						}
					}
				}
			}
		}
	}

	user.Meta.LastModified = now
	if err := s.repo.UpdateUser(ctx, orgID, user); err != nil {
		return nil, err
	}

	if wasActive && !user.Active {
		s.recordAudit(ctx, orgID, "", ActionSCIMUserDeactivated, uuid.MustParse(user.ID))
	} else {
		s.recordAudit(ctx, orgID, "", ActionSCIMUserUpdated, uuid.MustParse(user.ID))
	}

	return user, nil
}

// CreateGroup creates a SCIM group. Privileged role names are blocked from being group names.
func (s *SCIMService) CreateGroup(ctx context.Context, orgID uuid.UUID, group *SCIMGroup) (*SCIMGroup, error) {
	name := strings.TrimSpace(group.DisplayName)
	if name == "" {
		return nil, errors.New("displayName is required")
	}

	// Least Privilege Invariant: SCIM group cannot be named or mapped to root roles
	norm := strings.ToUpper(name)
	if norm == string(RoleOrgOwner) || norm == string(RoleOrgAdmin) || norm == string(RoleSecurityAdmin) {
		return nil, ErrSCIMPrivilegedGroupForbidden
	}

	if existing, err := s.repo.GetGroupByDisplayName(ctx, orgID, name); err == nil {
		return existing, nil // Idempotent return
	}

	now := time.Now().UTC()
	group.ID = uuid.New().String()
	group.Schemas = []string{SCIMGroupSchema}
	group.Meta = SCIMMeta{
		ResourceType: "Group",
		Created:      now,
		LastModified: now,
	}

	if err := s.repo.SaveGroup(ctx, orgID, group); err != nil {
		return nil, err
	}

	s.recordAudit(ctx, orgID, "", ActionSCIMGroupCreated, uuid.MustParse(group.ID))
	return group, nil
}

// GetGroup retrieves a SCIM group by ID.
func (s *SCIMService) GetGroup(ctx context.Context, orgID uuid.UUID, id string) (*SCIMGroup, error) {
	return s.repo.GetGroup(ctx, orgID, id)
}

func (s *SCIMService) recordAudit(ctx context.Context, orgID uuid.UUID, actorUserID, action string, entityID uuid.UUID) {
	if s.audit == nil {
		return
	}
	var actorUUID *uuid.UUID
	if aID, err := uuid.Parse(actorUserID); err == nil {
		actorUUID = &aID
	}
	evt := audit.Event{
		ID:          uuid.New(),
		TenantID:    &orgID,
		ActorUserID: actorUUID,
		ActorType:   audit.ActorSystem,
		Action:      action,
		EntityType:  "scim_resource",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
