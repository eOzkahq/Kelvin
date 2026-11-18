package findings

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultSearchLimit = 20
	MaxSearchLimit     = 100
)

var (
	ErrInvalidLimit  = errors.New("findings: query limit must be between 1 and 100")
	ErrInvalidOffset = errors.New("findings: query offset cannot be negative")
)

// FindingSearchQuery encapsulates all multi-facet filters, search keywords, sorting, and pagination.
type FindingSearchQuery struct {
	TenantID      uuid.UUID      `json:"tenant_id"`
	Query         string         `json:"q,omitempty"`
	Severity      string         `json:"severity,omitempty"`
	Status        FindingStatus  `json:"status,omitempty"`
	RiskPriority  string         `json:"risk_priority,omitempty"`
	Scanner       string         `json:"scanner,omitempty"`
	Target        string         `json:"target,omitempty"`
	AssessmentID  *uuid.UUID     `json:"assessment_id,omitempty"`
	FirstSeenFrom *time.Time     `json:"first_seen_from,omitempty"`
	FirstSeenTo   *time.Time     `json:"first_seen_to,omitempty"`
	LastSeenFrom  *time.Time     `json:"last_seen_from,omitempty"`
	LastSeenTo    *time.Time     `json:"last_seen_to,omitempty"`
	IsSuppressed  *bool          `json:"is_suppressed,omitempty"`
	SortBy        string         `json:"sort_by,omitempty"` // "severity", "risk_score", "created_at", "first_seen_at", "last_seen_at", "title"
	SortOrder     string         `json:"sort_order,omitempty"` // "asc", "desc"
	Limit         int            `json:"limit,omitempty"`
	Offset        int            `json:"offset,omitempty"`
}

// FindingSearchResult holds paginated results and total matched count.
type FindingSearchResult struct {
	Items      []*PersistentFinding `json:"items"`
	TotalCount int                  `json:"total_count"`
	Limit      int                  `json:"limit"`
	Offset     int                  `json:"offset"`
}

// FindingDashboardMetrics aggregates security posture and progress counters.
type FindingDashboardMetrics struct {
	TotalFindings       int            `json:"total_findings"`
	OpenFindings        int            `json:"open_findings"`
	ResolvedFindings    int            `json:"resolved_findings"`
	SeverityBreakdown   map[string]int `json:"severity_breakdown"`
	StatusBreakdown     map[string]int `json:"status_breakdown"`
	PriorityBreakdown   map[string]int `json:"priority_breakdown"`
	RemediationProgress map[string]int `json:"remediation_progress"`
}

// Severity rank for deterministic sorting
var severityRank = map[string]int{
	"CRITICAL": 5,
	"HIGH":     4,
	"MEDIUM":   3,
	"LOW":      2,
	"INFO":     1,
}

// FindingSearchEngine defines the querying and aggregation capabilities.
type FindingSearchEngine interface {
	SearchFindings(ctx context.Context, q FindingSearchQuery) (*FindingSearchResult, error)
	GetDashboardMetrics(ctx context.Context, tenantID uuid.UUID) (*FindingDashboardMetrics, error)
}

// MemoryFindingSearchEngine provides a fully functional in-memory search and dashboard engine.
type MemoryFindingSearchEngine struct {
	mu           sync.RWMutex
	findings     map[uuid.UUID]*PersistentFinding
	remediations map[uuid.UUID][]RemediationTask
	suppressions map[uuid.UUID]bool // findingID -> isSuppressed
}

// NewMemoryFindingSearchEngine constructs an in-memory search engine.
func NewMemoryFindingSearchEngine() *MemoryFindingSearchEngine {
	return &MemoryFindingSearchEngine{
		findings:     make(map[uuid.UUID]*PersistentFinding),
		remediations: make(map[uuid.UUID][]RemediationTask),
		suppressions: make(map[uuid.UUID]bool),
	}
}

// IndexFinding adds or updates a finding in the search engine index.
func (e *MemoryFindingSearchEngine) IndexFinding(f *PersistentFinding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.findings[f.ID] = f
}

// IndexRemediationTask links a remediation task for metrics.
func (e *MemoryFindingSearchEngine) IndexRemediationTask(task RemediationTask) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.remediations[task.FindingID] = append(e.remediations[task.FindingID], task)
}

// SetSuppressed marks a finding suppression state.
func (e *MemoryFindingSearchEngine) SetSuppressed(findingID uuid.UUID, suppressed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.suppressions[findingID] = suppressed
}

// SearchFindings executes filtered, sorted, paginated search over findings.
func (e *MemoryFindingSearchEngine) SearchFindings(_ context.Context, q FindingSearchQuery) (*FindingSearchResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if q.TenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}
	if q.Limit <= 0 {
		q.Limit = DefaultSearchLimit
	}
	if q.Limit > MaxSearchLimit {
		return nil, ErrInvalidLimit
	}
	if q.Offset < 0 {
		return nil, ErrInvalidOffset
	}

	var matched []*PersistentFinding

	for _, f := range e.findings {
		// 1. Tenant boundary
		if f.TenantID != q.TenantID {
			continue
		}

		// 2. Severity filter
		if q.Severity != "" && !strings.EqualFold(f.Severity, q.Severity) {
			continue
		}

		// 3. Status filter
		if q.Status != "" && CanonicalStatus(f.Status) != CanonicalStatus(q.Status) {
			continue
		}

		// 4. Risk priority band
		if q.RiskPriority != "" && !strings.EqualFold(string(f.RiskPriorityBand), q.RiskPriority) {
			continue
		}

		// 5. Scanner filter
		if q.Scanner != "" {
			scannerType := getFindingScannerType(f)
			if !strings.EqualFold(scannerType, q.Scanner) {
				continue
			}
		}

		// 6. Target filter
		if q.Target != "" && !strings.Contains(strings.ToLower(f.AffectedEndpoint), strings.ToLower(q.Target)) {
			continue
		}

		// 7. Assessment ID
		if q.AssessmentID != nil && f.AssessmentID != *q.AssessmentID {
			continue
		}

		// 8. Timestamps
		if q.FirstSeenFrom != nil && f.FirstSeenAt.Before(*q.FirstSeenFrom) {
			continue
		}
		if q.FirstSeenTo != nil && f.FirstSeenAt.After(*q.FirstSeenTo) {
			continue
		}
		if q.LastSeenFrom != nil && f.LastSeenAt.Before(*q.LastSeenFrom) {
			continue
		}
		if q.LastSeenTo != nil && f.LastSeenAt.After(*q.LastSeenTo) {
			continue
		}

		// 9. Suppression state
		if q.IsSuppressed != nil {
			isSupp := e.suppressions[f.ID]
			if isSupp != *q.IsSuppressed {
				continue
			}
		}

		// 10. Text search
		if q.Query != "" {
			queryLower := strings.ToLower(q.Query)
			matches := strings.Contains(strings.ToLower(f.Title), queryLower) ||
				strings.Contains(strings.ToLower(f.AffectedEndpoint), queryLower) ||
				strings.Contains(strings.ToLower(f.CWEID), queryLower)
			if !matches {
				for _, cve := range f.CVEIDs {
					if strings.Contains(strings.ToLower(cve), queryLower) {
						matches = true
						break
					}
				}
			}
			if !matches {
				continue
			}
		}

		matched = append(matched, f)
	}

	// Stable Sort
	sortOrderDesc := strings.ToLower(q.SortOrder) != "asc" // default desc
	sort.Slice(matched, func(i, j int) bool {
		a, b := matched[i], matched[j]
		switch strings.ToLower(q.SortBy) {
		case "severity":
			rankA := severityRank[strings.ToUpper(a.Severity)]
			rankB := severityRank[strings.ToUpper(b.Severity)]
			if rankA != rankB {
				if sortOrderDesc {
					return rankA > rankB
				}
				return rankA < rankB
			}
		case "risk_score":
			var scoreA, scoreB float64
			if a.RiskScore != nil {
				scoreA = *a.RiskScore
			}
			if b.RiskScore != nil {
				scoreB = *b.RiskScore
			}
			if scoreA != scoreB {
				if sortOrderDesc {
					return scoreA > scoreB
				}
				return scoreA < scoreB
			}
		case "title":
			if a.Title != b.Title {
				if sortOrderDesc {
					return a.Title > b.Title
				}
				return a.Title < b.Title
			}
		case "first_seen_at":
			if !a.FirstSeenAt.Equal(b.FirstSeenAt) {
				if sortOrderDesc {
					return a.FirstSeenAt.After(b.FirstSeenAt)
				}
				return a.FirstSeenAt.Before(b.FirstSeenAt)
			}
		default: // "last_seen_at" or default
			if !a.LastSeenAt.Equal(b.LastSeenAt) {
				if sortOrderDesc {
					return a.LastSeenAt.After(b.LastSeenAt)
				}
				return a.LastSeenAt.Before(b.LastSeenAt)
			}
		}
		// Tie-break stably by ID
		return a.ID.String() < b.ID.String()
	})

	totalCount := len(matched)
	start := q.Offset
	if start > totalCount {
		start = totalCount
	}
	end := start + q.Limit
	if end > totalCount {
		end = totalCount
	}

	paged := matched[start:end]
	if paged == nil {
		paged = make([]*PersistentFinding, 0)
	}

	return &FindingSearchResult{
		Items:      paged,
		TotalCount: totalCount,
		Limit:      q.Limit,
		Offset:     q.Offset,
	}, nil
}

// GetDashboardMetrics compiles KPI dashboard aggregates strictly for the tenant.
func (e *MemoryFindingSearchEngine) GetDashboardMetrics(_ context.Context, tenantID uuid.UUID) (*FindingDashboardMetrics, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if tenantID == uuid.Nil {
		return nil, ErrMissingTenantID
	}

	metrics := &FindingDashboardMetrics{
		SeverityBreakdown: map[string]int{
			"CRITICAL": 0,
			"HIGH":     0,
			"MEDIUM":   0,
			"LOW":      0,
			"INFO":     0,
		},
		StatusBreakdown: map[string]int{
			"NEW":            0,
			"CONFIRMED":      0,
			"IN_PROGRESS":    0,
			"RESOLVED":       0,
			"REOPENED":       0,
			"FALSE_POSITIVE": 0,
			"ACCEPTED_RISK":  0,
		},
		PriorityBreakdown: map[string]int{
			"P1": 0,
			"P2": 0,
			"P3": 0,
			"P4": 0,
			"P5": 0,
		},
		RemediationProgress: map[string]int{
			"OPEN":                    0,
			"IN_PROGRESS":             0,
			"READY_FOR_VERIFICATION": 0,
			"COMPLETED":               0,
			"BLOCKED":                 0,
		},
	}

	for _, f := range e.findings {
		if f.TenantID != tenantID {
			continue
		}
		metrics.TotalFindings++

		// Severity
		sev := strings.ToUpper(f.Severity)
		if _, ok := metrics.SeverityBreakdown[sev]; ok {
			metrics.SeverityBreakdown[sev]++
		}

		// Status
		st := string(CanonicalStatus(f.Status))
		if _, ok := metrics.StatusBreakdown[st]; ok {
			metrics.StatusBreakdown[st]++
		}

		if CanonicalStatus(f.Status) == StatusResolved {
			metrics.ResolvedFindings++
		} else {
			metrics.OpenFindings++
		}

		// Priority
		if f.RiskPriorityBand != "" {
			pb := string(f.RiskPriorityBand)
			if _, ok := metrics.PriorityBreakdown[pb]; ok {
				metrics.PriorityBreakdown[pb]++
			}
		}

		// Remediation
		if tasks, ok := e.remediations[f.ID]; ok {
			for _, t := range tasks {
				st := string(t.State)
				if _, ok := metrics.RemediationProgress[st]; ok {
					metrics.RemediationProgress[st]++
				}
			}
		}
	}

	return metrics, nil
}
