package governance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrQuotaExceeded     = errors.New("governance: tenant resource quota exceeded")
	ErrInvalidQuotaValue = errors.New("governance: quota value must be strictly positive")
)

const (
	DimConcurrentScans    = "concurrent_scans"
	DimMonthlyScanHours   = "monthly_scan_hours"
	DimStorageGB          = "storage_gb"
	DimServiceIdentities  = "service_identities"
	DimMonthlyEvents      = "monthly_events"

	DefaultMaxConcurrentScans   = 5
	DefaultMaxMonthlyScanHours  = 100.0
	DefaultMaxStorageGB         = 50.0
	DefaultMaxServiceIdentities = 20
	DefaultMaxMonthlyEvents     = 10000
)

// QuotaExceededError gives structured diagnostic detail on the throttled dimension.
type QuotaExceededError struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	Dimension string    `json:"dimension"`
	Limit     float64   `json:"limit"`
	Current   float64   `json:"current"`
	Requested float64   `json:"requested"`
}

func (e *QuotaExceededError) Error() string {
	return fmt.Sprintf("governance: quota exceeded for '%s': requested %.2f, current %.2f, limit %.2f",
		e.Dimension, e.Requested, e.Current, e.Limit)
}

func (e *QuotaExceededError) Is(target error) bool {
	return target == ErrQuotaExceeded
}

// TenantQuota defines operational capacity bounds for a tenant.
type TenantQuota struct {
	TenantID             uuid.UUID `json:"tenant_id"`
	MaxConcurrentScans   int       `json:"max_concurrent_scans"`
	MaxMonthlyScanHours  float64   `json:"max_monthly_scan_hours"`
	MaxStorageGB         float64   `json:"max_storage_gb"`
	MaxServiceIdentities int       `json:"max_service_identities"`
	MaxMonthlyEvents     int       `json:"max_monthly_events"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// UsageSummary aggregates real-time usage against provisioned quotas.
type UsageSummary struct {
	TenantID                uuid.UUID          `json:"tenant_id"`
	Period                  string             `json:"period"` // YYYY-MM
	ActiveConcurrentScans   int                `json:"active_concurrent_scans"`
	ConsumedScanHours       float64            `json:"consumed_scan_hours"`
	CurrentStorageGB        float64            `json:"current_storage_gb"`
	ActiveServiceIdentities int                `json:"active_service_identities"`
	MonthlyEvents           int                `json:"monthly_events"`
	Quota                   TenantQuota        `json:"quota"`
	PercentUtilized         map[string]float64 `json:"percent_utilized"`
}

// QuotaManager provides atomic, concurrency-safe tracking and gatekeeping for tenant quotas.
type QuotaManager struct {
	mu         sync.Mutex
	quotas     map[uuid.UUID]*TenantQuota
	concurrent map[uuid.UUID]int
	usage      map[string]float64 // key: tenantID:period:dimension
}

func NewQuotaManager() *QuotaManager {
	return &QuotaManager{
		quotas:     make(map[uuid.UUID]*TenantQuota),
		concurrent: make(map[uuid.UUID]int),
		usage:      make(map[string]float64),
	}
}

// SetQuota establishes tenant limits within platform bounds.
func (m *QuotaManager) SetQuota(q TenantQuota) error {
	if q.TenantID == uuid.Nil {
		return ErrMissingPolicyTenant
	}
	if q.MaxConcurrentScans <= 0 || q.MaxMonthlyScanHours <= 0 || q.MaxStorageGB <= 0 ||
		q.MaxServiceIdentities <= 0 || q.MaxMonthlyEvents <= 0 {
		return ErrInvalidQuotaValue
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	q.UpdatedAt = time.Now().UTC()
	m.quotas[q.TenantID] = &q
	return nil
}

// GetQuota retrieves tenant quota or defaults.
func (m *QuotaManager) GetQuota(tenantID uuid.UUID) TenantQuota {
	m.mu.Lock()
	defer m.mu.Unlock()

	if q, ok := m.quotas[tenantID]; ok {
		return *q
	}
	return TenantQuota{
		TenantID:             tenantID,
		MaxConcurrentScans:   DefaultMaxConcurrentScans,
		MaxMonthlyScanHours:  DefaultMaxMonthlyScanHours,
		MaxStorageGB:         DefaultMaxStorageGB,
		MaxServiceIdentities: DefaultMaxServiceIdentities,
		MaxMonthlyEvents:     DefaultMaxMonthlyEvents,
		UpdatedAt:            time.Now().UTC(),
	}
}

func currentPeriod() string {
	return time.Now().UTC().Format("2006-01")
}

// AcquireConcurrentScan reserves an active scan execution slot atomically.
// Returns a release function that must be called when the scan finishes.
func (m *QuotaManager) AcquireConcurrentScan(ctx context.Context, tenantID uuid.UUID) (func(), error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingPolicyTenant
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	quota := TenantQuota{
		MaxConcurrentScans: DefaultMaxConcurrentScans,
	}
	if q, ok := m.quotas[tenantID]; ok {
		quota = *q
	}

	active := m.concurrent[tenantID]
	if active >= quota.MaxConcurrentScans {
		return nil, &QuotaExceededError{
			TenantID:  tenantID,
			Dimension: DimConcurrentScans,
			Limit:     float64(quota.MaxConcurrentScans),
			Current:   float64(active),
			Requested: 1,
		}
	}

	m.concurrent[tenantID] = active + 1

	var once sync.Once
	release := func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			if m.concurrent[tenantID] > 0 {
				m.concurrent[tenantID]--
			}
		})
	}

	return release, nil
}

// RecordUsage atomically consumes resources in a specified dimension, checking limits.
func (m *QuotaManager) RecordUsage(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	amount float64,
) error {
	if tenantID == uuid.Nil {
		return ErrMissingPolicyTenant
	}
	if amount < 0 {
		return errors.New("governance: usage delta cannot be negative")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	quota := TenantQuota{
		MaxMonthlyScanHours:  DefaultMaxMonthlyScanHours,
		MaxStorageGB:         DefaultMaxStorageGB,
		MaxServiceIdentities: DefaultMaxServiceIdentities,
		MaxMonthlyEvents:     DefaultMaxMonthlyEvents,
	}
	if q, ok := m.quotas[tenantID]; ok {
		quota = *q
	}

	period := currentPeriod()
	key := fmt.Sprintf("%s:%s:%s", tenantID, period, dimension)
	current := m.usage[key]

	var limit float64
	switch dimension {
	case DimMonthlyScanHours:
		limit = quota.MaxMonthlyScanHours
	case DimStorageGB:
		limit = quota.MaxStorageGB
	case DimServiceIdentities:
		limit = float64(quota.MaxServiceIdentities)
	case DimMonthlyEvents:
		limit = float64(quota.MaxMonthlyEvents)
	default:
		return fmt.Errorf("governance: unrecognized usage dimension '%s'", dimension)
	}

	if current+amount > limit {
		return &QuotaExceededError{
			TenantID:  tenantID,
			Dimension: dimension,
			Limit:     limit,
			Current:   current,
			Requested: amount,
		}
	}

	m.usage[key] = current + amount
	return nil
}

// GetUsageSummary aggregates utilization statistics for authorized tenant dashboards.
func (m *QuotaManager) GetUsageSummary(ctx context.Context, tenantID uuid.UUID) (*UsageSummary, error) {
	if tenantID == uuid.Nil {
		return nil, ErrMissingPolicyTenant
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	quota := TenantQuota{
		TenantID:             tenantID,
		MaxConcurrentScans:   DefaultMaxConcurrentScans,
		MaxMonthlyScanHours:  DefaultMaxMonthlyScanHours,
		MaxStorageGB:         DefaultMaxStorageGB,
		MaxServiceIdentities: DefaultMaxServiceIdentities,
		MaxMonthlyEvents:     DefaultMaxMonthlyEvents,
	}
	if q, ok := m.quotas[tenantID]; ok {
		quota = *q
	}

	period := currentPeriod()
	scanHours := m.usage[fmt.Sprintf("%s:%s:%s", tenantID, period, DimMonthlyScanHours)]
	storage := m.usage[fmt.Sprintf("%s:%s:%s", tenantID, period, DimStorageGB)]
	serviceIDs := int(m.usage[fmt.Sprintf("%s:%s:%s", tenantID, period, DimServiceIdentities)])
	events := int(m.usage[fmt.Sprintf("%s:%s:%s", tenantID, period, DimMonthlyEvents)])
	activeConcurrent := m.concurrent[tenantID]

	percentUtil := map[string]float64{
		DimConcurrentScans:   (float64(activeConcurrent) / float64(quota.MaxConcurrentScans)) * 100,
		DimMonthlyScanHours:  (scanHours / quota.MaxMonthlyScanHours) * 100,
		DimStorageGB:         (storage / quota.MaxStorageGB) * 100,
		DimServiceIdentities: (float64(serviceIDs) / float64(quota.MaxServiceIdentities)) * 100,
		DimMonthlyEvents:     (float64(events) / float64(quota.MaxMonthlyEvents)) * 100,
	}

	return &UsageSummary{
		TenantID:                tenantID,
		Period:                  period,
		ActiveConcurrentScans:   activeConcurrent,
		ConsumedScanHours:       scanHours,
		CurrentStorageGB:        storage,
		ActiveServiceIdentities: serviceIDs,
		MonthlyEvents:           events,
		Quota:                   quota,
		PercentUtilized:         percentUtil,
	}, nil
}
