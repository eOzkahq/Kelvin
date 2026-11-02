package audit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/integrations"
	"github.com/kelvin/kelvin/apps/api/internal/redaction"
)

var (
	ErrAuditForbidden    = errors.New("audit: caller lacks 'audit:read' permission or auditor role")
	ErrMissingTenantID   = errors.New("audit: tenant isolation requires a valid tenant ID")
	ErrInvalidTimeRange  = errors.New("audit: 'from_time' must not be after 'to_time'")
	ErrLimitExceeded     = errors.New("audit: query limit exceeds maximum allowed limit (100)")
)

const (
	DefaultLimit = 20
	MaxLimit     = 100

	PermissionAuditRead = "audit:read"
)

// Principal represents the caller requesting audit log access.
type Principal struct {
	UserID      uuid.UUID `json:"user_id"`
	TenantID    uuid.UUID `json:"tenant_id"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions"`
}

// CheckAuditAccess verifies that caller is authorized to view audit trails.
func CheckAuditAccess(p Principal) error {
	for _, perm := range p.Permissions {
		if perm == PermissionAuditRead || perm == "*" || perm == "audit:*" {
			return nil
		}
	}

	normalizedRole := strings.ToUpper(strings.TrimSpace(p.Role))
	switch normalizedRole {
	case "ORG_OWNER", "SECURITY_OFFICER", "COMPLIANCE_AUDITOR", "SYSTEM_ADMIN":
		return nil
	default:
		return ErrAuditForbidden
	}
}

// SearchFilter specifies multi-dimensional criteria for querying audit trails.
type SearchFilter struct {
	TenantID       uuid.UUID      `json:"tenant_id"`
	ActorUserID    *uuid.UUID     `json:"actor_user_id,omitempty"`
	ActorType      *ActorType     `json:"actor_type,omitempty"`
	Action         string         `json:"action,omitempty"`
	EntityType     string         `json:"entity_type,omitempty"`
	EntityID       *uuid.UUID     `json:"entity_id,omitempty"`
	CorrelationID  string         `json:"correlation_id,omitempty"`
	FromTime       *time.Time     `json:"from_time,omitempty"`
	ToTime         *time.Time     `json:"to_time,omitempty"`
	MetadataFilter map[string]any `json:"metadata_filter,omitempty"`
	Limit          int            `json:"limit,omitempty"`
	Offset         int            `json:"offset,omitempty"`
}

// SearchResult contains paginated audit events with total count and metadata.
type SearchResult struct {
	Events     []Event `json:"events"`
	TotalCount int     `json:"total_count"`
	Limit      int     `json:"limit"`
	Offset     int     `json:"offset"`
	HasMore    bool    `json:"has_more"`
}

// SearchService handles auditable read-only queries with defense-in-depth redaction.
type SearchService struct {
	db       *sql.DB
	redactor *redaction.Redactor
}

// NewSearchService creates a new audit SearchService.
func NewSearchService(db *sql.DB) *SearchService {
	return &SearchService{
		db:       db,
		redactor: redaction.NewDefaultRedactor(),
	}
}

// SanitizeEventPayload scrubs credentials, passwords, and tokens from audit event payloads.
func (s *SearchService) SanitizeEventPayload(evt *Event) {
	if len(evt.Payload) == 0 {
		return
	}
	redacted := integrations.RedactSensitiveContent(s.redactor.RedactString(string(evt.Payload)))
	evt.Payload = json.RawMessage(redacted)
}

// ValidateFilter validates search limits, tenant isolation, and time ranges.
func (s *SearchService) ValidateFilter(filter *SearchFilter) error {
	if filter.TenantID == uuid.Nil {
		return ErrMissingTenantID
	}
	if filter.FromTime != nil && filter.ToTime != nil && filter.FromTime.After(*filter.ToTime) {
		return ErrInvalidTimeRange
	}
	if filter.Limit <= 0 {
		filter.Limit = DefaultLimit
	}
	if filter.Limit > MaxLimit {
		return ErrLimitExceeded
	}
	if filter.Offset < 0 {
		filter.Offset = 0
	}
	return nil
}

// FilterEventsInMemory executes search and filtering over in-memory events for testing and isolated verification.
func (s *SearchService) FilterEventsInMemory(events []Event, filter SearchFilter) (*SearchResult, error) {
	if err := s.ValidateFilter(&filter); err != nil {
		return nil, err
	}

	var matched []Event
	for _, e := range events {
		if e.TenantID == nil || *e.TenantID != filter.TenantID {
			continue
		}
		if filter.ActorUserID != nil && (e.ActorUserID == nil || *e.ActorUserID != *filter.ActorUserID) {
			continue
		}
		if filter.ActorType != nil && e.ActorType != *filter.ActorType {
			continue
		}
		if filter.Action != "" && !strings.EqualFold(e.Action, filter.Action) {
			continue
		}
		if filter.EntityType != "" && !strings.EqualFold(e.EntityType, filter.EntityType) {
			continue
		}
		if filter.EntityID != nil && (e.EntityID == nil || *e.EntityID != *filter.EntityID) {
			continue
		}
		if filter.CorrelationID != "" && e.CorrelationID != filter.CorrelationID {
			continue
		}
		if filter.FromTime != nil && e.CreatedAt.Before(*filter.FromTime) {
			continue
		}
		if filter.ToTime != nil && e.CreatedAt.After(*filter.ToTime) {
			continue
		}

		// Metadata key/value matching
		if len(filter.MetadataFilter) > 0 {
			var payloadMap map[string]any
			if err := json.Unmarshal(e.Payload, &payloadMap); err == nil {
				matchesAll := true
				for k, v := range filter.MetadataFilter {
					if payloadVal, ok := payloadMap[k]; !ok || fmt.Sprintf("%v", payloadVal) != fmt.Sprintf("%v", v) {
						matchesAll = false
						break
					}
				}
				if !matchesAll {
					continue
				}
			}
		}

		// Clone and sanitize
		sanitized := e
		s.SanitizeEventPayload(&sanitized)
		matched = append(matched, sanitized)
	}

	// Stable sort: CreatedAt DESC, ID DESC
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].ID.String() > matched[j].ID.String()
		}
		return matched[i].CreatedAt.After(matched[j].CreatedAt)
	})

	totalCount := len(matched)
	start := filter.Offset
	if start > totalCount {
		start = totalCount
	}
	end := start + filter.Limit
	if end > totalCount {
		end = totalCount
	}

	paginated := matched[start:end]
	hasMore := end < totalCount

	return &SearchResult{
		Events:     paginated,
		TotalCount: totalCount,
		Limit:      filter.Limit,
		Offset:     filter.Offset,
		HasMore:    hasMore,
	}, nil
}

// BuildSearchQuery builds parameterized SQL query and argument list for PostgreSQL execution.
func (s *SearchService) BuildSearchQuery(filter SearchFilter) (query string, countQuery string, args []any) {
	var whereClauses []string
	idx := 1

	whereClauses = append(whereClauses, fmt.Sprintf("tenant_id = $%d", idx))
	args = append(args, filter.TenantID)
	idx++

	if filter.ActorUserID != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("actor_user_id = $%d", idx))
		args = append(args, *filter.ActorUserID)
		idx++
	}
	if filter.ActorType != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("actor_type = $%d", idx))
		args = append(args, string(*filter.ActorType))
		idx++
	}
	if filter.Action != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("action ILIKE $%d", idx))
		args = append(args, filter.Action)
		idx++
	}
	if filter.EntityType != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("entity_type = $%d", idx))
		args = append(args, filter.EntityType)
		idx++
	}
	if filter.EntityID != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("entity_id = $%d", idx))
		args = append(args, *filter.EntityID)
		idx++
	}
	if filter.CorrelationID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("correlation_id = $%d", idx))
		args = append(args, filter.CorrelationID)
		idx++
	}
	if filter.FromTime != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.FromTime)
		idx++
	}
	if filter.ToTime != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.ToTime)
		idx++
	}
	if len(filter.MetadataFilter) > 0 {
		metaJSON, _ := json.Marshal(filter.MetadataFilter)
		whereClauses = append(whereClauses, fmt.Sprintf("payload @> $%d::jsonb", idx))
		args = append(args, string(metaJSON))
		idx++
	}

	whereSQL := strings.Join(whereClauses, " AND ")
	countQuery = fmt.Sprintf("SELECT COUNT(*) FROM audit_log WHERE %s", whereSQL)

	query = fmt.Sprintf(`
		SELECT id, tenant_id, actor_user_id, actor_type, action, entity_type, entity_id, payload, correlation_id, created_at
		FROM audit_log
		WHERE %s
		ORDER BY created_at DESC, id DESC
		LIMIT $%d OFFSET $%d
	`, whereSQL, idx, idx+1)

	return query, countQuery, args
}
