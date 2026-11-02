package policy

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/api/internal/audit"
)

var (
	ErrInvalidTimeZone       = errors.New("invalid IANA time zone identifier")
	ErrInvalidTimeFormat     = errors.New("invalid time format: must be HH:MM in 24-hour notation")
	ErrInvalidDaysOfWeek     = errors.New("days_of_week must contain integers between 1 (Monday) and 7 (Sunday)")
	ErrWindowNotFound        = errors.New("scheduling window not found")
	ErrExecutionBlackedOut   = errors.New("assessment execution prohibited by active blackout window policy")
)

const (
	WindowTypeMaintenance = "MAINTENANCE"
	WindowTypeBlackout    = "BLACKOUT"
)

const (
	BlackoutActionHold   = "HOLD"
	BlackoutActionCancel = "CANCEL"
)

const (
	VerdictDispatch = "DISPATCH"
	VerdictHold     = "HOLD"
	VerdictCancel   = "CANCEL"
)

const (
	ActionWindowConfigured = "scheduling_window.configured"
	ActionWindowEvaluated  = "scheduling_window.evaluated"
)

// SchedulingWindow defines a recurring temporal boundary for scans.
type SchedulingWindow struct {
	ID                 uuid.UUID `json:"id"`
	OrganizationID     uuid.UUID `json:"organization_id"`
	Name               string    `json:"name"`
	WindowType         string    `json:"window_type"` // MAINTENANCE, BLACKOUT
	TimeZone           string    `json:"time_zone"`   // IANA time zone e.g. "UTC", "America/New_York"
	DaysOfWeek         []int     `json:"days_of_week"` // 1=Monday ... 7=Sunday
	StartTime          string    `json:"start_time"`  // "HH:MM"
	EndTime            string    `json:"end_time"`    // "HH:MM"
	BlackoutAction     string    `json:"blackout_action"` // HOLD, CANCEL
	AppliesToManual    bool      `json:"applies_to_manual"`
	AppliesToScheduled bool      `json:"applies_to_scheduled"`
	Status             string    `json:"status"` // ACTIVE, DISABLED
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// ScheduleEvaluationResult reports the deterministic execution decision for an assessment trigger.
type ScheduleEvaluationResult struct {
	CanExecuteNow      bool       `json:"can_execute_now"`
	Verdict            string     `json:"verdict"` // DISPATCH, HOLD, CANCEL
	NextAvailableTime  *time.Time `json:"next_available_time,omitempty"`
	MatchedWindowID    *uuid.UUID `json:"matched_window_id,omitempty"`
	MatchedWindowName  string     `json:"matched_window_name,omitempty"`
	Reason             string     `json:"reason"`
}

// SchedulingWindowRepository defines persistence operations for scheduling windows.
type SchedulingWindowRepository interface {
	SaveWindow(ctx context.Context, w *SchedulingWindow) error
	GetWindow(ctx context.Context, id uuid.UUID) (*SchedulingWindow, error)
	ListActiveWindows(ctx context.Context, orgID uuid.UUID) ([]*SchedulingWindow, error)
	UpdateWindow(ctx context.Context, w *SchedulingWindow) error
}

// MemorySchedulingWindowRepository provides an in-memory implementation of SchedulingWindowRepository.
type MemorySchedulingWindowRepository struct {
	mu      sync.RWMutex
	windows map[uuid.UUID]*SchedulingWindow
}

func NewMemorySchedulingWindowRepository() *MemorySchedulingWindowRepository {
	return &MemorySchedulingWindowRepository{
		windows: make(map[uuid.UUID]*SchedulingWindow),
	}
}

func (m *MemorySchedulingWindowRepository) SaveWindow(ctx context.Context, w *SchedulingWindow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.windows[w.ID] = w
	return nil
}

func (m *MemorySchedulingWindowRepository) GetWindow(ctx context.Context, id uuid.UUID) (*SchedulingWindow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	w, ok := m.windows[id]
	if !ok {
		return nil, ErrWindowNotFound
	}
	return w, nil
}

func (m *MemorySchedulingWindowRepository) ListActiveWindows(ctx context.Context, orgID uuid.UUID) ([]*SchedulingWindow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var list []*SchedulingWindow
	for _, w := range m.windows {
		if w.OrganizationID == orgID && w.Status == "ACTIVE" {
			list = append(list, w)
		}
	}
	return list, nil
}

func (m *MemorySchedulingWindowRepository) UpdateWindow(ctx context.Context, w *SchedulingWindow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.windows[w.ID]; !ok {
		return ErrWindowNotFound
	}
	m.windows[w.ID] = w
	return nil
}

// SchedulingService manages maintenance windows and blackout periods with explicit timezone semantics.
type SchedulingService struct {
	repo  SchedulingWindowRepository
	audit audit.Recorder
}

func NewSchedulingService(repo SchedulingWindowRepository, audit audit.Recorder) *SchedulingService {
	return &SchedulingService{
		repo:  repo,
		audit: audit,
	}
}

// ConfigureWindow registers or updates a scheduling window with validation.
func (s *SchedulingService) ConfigureWindow(ctx context.Context, actorUserID string, window *SchedulingWindow) error {
	if window.OrganizationID == uuid.Nil {
		return errors.New("organization ID is required")
	}

	if strings.TrimSpace(window.TimeZone) == "" {
		window.TimeZone = "UTC"
	}

	// Validate IANA Time Zone
	loc, err := time.LoadLocation(window.TimeZone)
	if err != nil || loc == nil {
		return fmt.Errorf("%w: %q", ErrInvalidTimeZone, window.TimeZone)
	}

	// Validate StartTime and EndTime
	if !isValidTimeFormat(window.StartTime) || !isValidTimeFormat(window.EndTime) {
		return ErrInvalidTimeFormat
	}

	// Validate DaysOfWeek
	if len(window.DaysOfWeek) == 0 {
		return errors.New("at least one day of week must be selected")
	}
	for _, d := range window.DaysOfWeek {
		if d < 1 || d > 7 {
			return ErrInvalidDaysOfWeek
		}
	}

	if window.WindowType != WindowTypeMaintenance && window.WindowType != WindowTypeBlackout {
		return errors.New("window_type must be MAINTENANCE or BLACKOUT")
	}

	now := time.Now().UTC()
	if window.ID == uuid.Nil {
		window.ID = uuid.New()
		window.CreatedAt = now
	}
	window.UpdatedAt = now
	if window.Status == "" {
		window.Status = "ACTIVE"
	}

	if err := s.repo.SaveWindow(ctx, window); err != nil {
		return err
	}

	s.recordAudit(ctx, window.OrganizationID, actorUserID, ActionWindowConfigured, window.ID)
	return nil
}

// EvaluateExecution determines whether an assessment can execute immediately, be delayed (HOLD), or be CANCELLED.
func (s *SchedulingService) EvaluateExecution(
	ctx context.Context,
	orgID uuid.UUID,
	evalTime time.Time,
	isManual bool,
) (*ScheduleEvaluationResult, error) {
	windows, err := s.repo.ListActiveWindows(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// 1. Blackout Windows Check (Highest priority prohibition)
	for _, w := range windows {
		if w.WindowType != WindowTypeBlackout {
			continue
		}

		// Check if window applies to this execution mode
		if (isManual && !w.AppliesToManual) || (!isManual && !w.AppliesToScheduled) {
			continue
		}

		inWindow, endLocalTime, err := isTimeInWindow(evalTime, w)
		if err != nil {
			return nil, err
		}

		if inWindow {
			res := &ScheduleEvaluationResult{
				CanExecuteNow:     false,
				MatchedWindowID:   &w.ID,
				MatchedWindowName: w.Name,
			}

			if w.BlackoutAction == BlackoutActionCancel {
				res.Verdict = VerdictCancel
				res.Reason = fmt.Sprintf("execution cancelled by active blackout window %q", w.Name)
			} else {
				res.Verdict = VerdictHold
				res.Reason = fmt.Sprintf("execution held until blackout window %q concludes", w.Name)
				res.NextAvailableTime = &endLocalTime
			}

			s.recordAudit(ctx, orgID, "", ActionWindowEvaluated, w.ID)
			return res, nil
		}
	}

	// 2. Allowed Execution
	res := &ScheduleEvaluationResult{
		CanExecuteNow: true,
		Verdict:       VerdictDispatch,
		Reason:        "no active blackout window prohibits execution",
	}

	s.recordAudit(ctx, orgID, "", ActionWindowEvaluated, uuid.Nil)
	return res, nil
}

func isTimeInWindow(t time.Time, w *SchedulingWindow) (bool, time.Time, error) {
	loc, err := time.LoadLocation(w.TimeZone)
	if err != nil {
		return false, time.Time{}, err
	}

	localTime := t.In(loc)
	weekday := int(localTime.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday = 7 in ISO-8601
	}

	dayMatches := false
	for _, d := range w.DaysOfWeek {
		if d == weekday {
			dayMatches = true
			break
		}
	}
	if !dayMatches {
		return false, time.Time{}, nil
	}

	curHM := localTime.Format("15:04")
	if curHM >= w.StartTime && curHM < w.EndTime {
		// Compute window end in UTC
		endParts := strings.Split(w.EndTime, ":")
		endHour, _ := strconv.Atoi(endParts[0])
		endMin, _ := strconv.Atoi(endParts[1])

		endLocal := time.Date(
			localTime.Year(), localTime.Month(), localTime.Day(),
			endHour, endMin, 0, 0, loc,
		)
		return true, endLocal.UTC(), nil
	}

	return false, time.Time{}, nil
}

func isValidTimeFormat(s string) bool {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return false
	}
	h, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return h >= 0 && h <= 23 && m >= 0 && m <= 59
}

func (s *SchedulingService) recordAudit(ctx context.Context, orgID uuid.UUID, actorUserID, action string, entityID uuid.UUID) {
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
		EntityType:  "scheduling_window",
		EntityID:    &entityID,
		CreatedAt:   time.Now().UTC(),
	}
	_ = s.audit.Record(ctx, evt)
}
