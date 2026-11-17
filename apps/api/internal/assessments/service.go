package assessments

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	commonqueue "github.com/kelvin/kelvin/packages/common/queue"
	"github.com/kelvin/kelvin/packages/common/validation"
	"go.uber.org/zap"
)

type Service struct {
	repo                 Repository
	queue                commonqueue.IJobQueue
	canaryOnly           bool
	canaryAllowedTargets []string
	log                  *zap.Logger
}

func NewService(repo Repository, q commonqueue.IJobQueue, canaryOnly bool, allowedTargets []string, log *zap.Logger) *Service {
	if log == nil {
		log = zap.NewNop()
	}
	return &Service{
		repo:                 repo,
		queue:                q,
		canaryOnly:           canaryOnly,
		canaryAllowedTargets: allowedTargets,
		log:                  log,
	}
}

func (s *Service) CreateAssessment(ctx context.Context, tenantID, userID string, input CreateAssessmentInput) (*AssessmentRecord, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}

	// 1. Resolve Target Address
	targetAddress := strings.TrimSpace(input.TargetAddress)
	if targetAddress == "" && len(input.Targets) > 0 {
		targetAddress = strings.TrimSpace(input.Targets[0].Host)
	}
	if targetAddress == "" && input.TargetID != "" {
		targets, _ := s.repo.GetTargets(ctx, tenantID)
		for _, t := range targets {
			if t.ID == input.TargetID {
				targetAddress = t.Address
				break
			}
		}
	}
	if targetAddress == "" {
		return nil, ErrInvalidTarget
	}

	// 2. Validate Scope Confirmation
	if !input.AuthorizedScopeConfirmed {
		return nil, ErrScopeNotConfirmed
	}

	// 3. Enforce Canary Policy (ADR-0008 & Milestone 5/6/7 Canary Boundaries)
	if s.canaryOnly {
		if !IsCanaryTargetAllowed(targetAddress, s.canaryAllowedTargets) {
			s.log.Warn("assessment creation rejected by canary-only policy: target not permitted",
				zap.String("tenant_id", tenantID),
				zap.String("target", targetAddress),
			)
			return nil, fmt.Errorf("%w: target %q is outside staging canary allowlist", ErrCanaryTargetProhibited, targetAddress)
		}
	}

	// 4. Validate and resolve Profile
	profileID := strings.TrimSpace(input.ProfileID)
	if profileID == "" {
		profileID = "standard"
	}

	profiles, err := s.repo.GetProfiles(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch profiles: %w", err)
	}

	var selectedProfile *ScanProfile
	for i := range profiles {
		if strings.EqualFold(profiles[i].ID, profileID) || strings.EqualFold(profiles[i].Name, profileID) {
			selectedProfile = &profiles[i]
			break
		}
	}
	if selectedProfile == nil {
		// If custom UUID, accept as custom profile; otherwise reject
		if !validation.IsUUID(profileID) {
			return nil, ErrInvalidProfile
		}
		selectedProfile = &ScanProfile{
			ID:          profileID,
			Name:        "Custom Profile",
			Description: "Custom scan profile",
			Scanners:    []string{"nuclei"},
			RiskLevel:   "MEDIUM",
		}
	}

	// 5. Construct Assessment Record
	asmtID := uuid.New().String()
	name := strings.TrimSpace(input.Name)
	if name == "" {
		name = fmt.Sprintf("%s Assessment - %s", selectedProfile.Name, time.Now().Format("2006-01-02 15:04"))
	}

	record := &AssessmentRecord{
		ID:            asmtID,
		TenantID:      tenantID,
		Name:          name,
		TargetID:      input.TargetID,
		TargetAddress: targetAddress,
		ProfileID:     selectedProfile.ID,
		ProfileName:   selectedProfile.Name,
		Status:        StatusQueued,
		CreatedAt:     time.Now().UTC(),
	}

	// 6. Persist to Repository
	if err := s.repo.Create(ctx, record, selectedProfile); err != nil {
		return nil, fmt.Errorf("failed to create assessment record: %w", err)
	}

	// 7. Enqueue to Job Queue (Redis Stream kelvin:jobs:stream)
	if s.queue != nil {
		jobID := uuid.New().String()
		correlationID := uuid.New().String()

		deadlineSeconds := int64(input.TimeoutMinutes * 60)
		if deadlineSeconds <= 0 {
			deadlineSeconds = 600 // 10 minutes default
		}

		jobType := "ASSESSMENT"
		if len(selectedProfile.Scanners) == 1 {
			jobType = strings.ToUpper(selectedProfile.Scanners[0])
		}

		now := time.Now().UTC()
		expiresAt := now.Add(time.Duration(deadlineSeconds*2) * time.Second)

		targetID := input.TargetID
		if targetID == "" {
			targetID = uuid.New().String()
		}

		envelope := commonqueue.JobEnvelope{
			SchemaVersion:       2,
			JobID:               jobID,
			AssessmentID:        asmtID,
			TenantID:            tenantID,
			TargetID:            targetID,
			TargetAddress:       targetAddress,
			ScanProfile:         selectedProfile.ID,
			RequestedScanners:   selectedProfile.Scanners,
			RateLimit:           fmt.Sprintf("%d", input.RateLimit),
			HardDeadlineSeconds: deadlineSeconds,
			CreatedAt:           now,
			ExpiresAt:           expiresAt,
			CorrelationID:       correlationID,
		}

		payloadBytes, err := json.Marshal(envelope)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal job envelope: %w", err)
		}

		queueMsg := commonqueue.Message{
			Version:       2,
			ID:            jobID,
			AssessmentID:  asmtID,
			TenantID:      tenantID,
			CorrelationID: correlationID,
			Type:          jobType,
			Payload:       payloadBytes,
			MaxAttempts:   3,
		}

		if err := s.queue.Enqueue(ctx, queueMsg); err != nil {
			s.log.Error("failed to enqueue assessment job to queue", zap.String("assessment_id", asmtID), zap.Error(err))
			// Record error in assessment record
			_ = s.repo.UpdateStatus(ctx, tenantID, asmtID, StatusFailed, "failed to enqueue job: "+err.Error())
			return nil, fmt.Errorf("failed to enqueue assessment job: %w", err)
		}
		s.log.Info("assessment job enqueued successfully",
			zap.String("assessment_id", asmtID),
			zap.String("job_id", jobID),
			zap.String("job_type", jobType),
			zap.String("target", targetAddress),
		)
	}

	return record, nil
}

func (s *Service) GetAssessment(ctx context.Context, tenantID, id string) (*AssessmentDetail, error) {
	if tenantID == "" || id == "" {
		return nil, ErrAssessmentNotFound
	}
	return s.repo.GetByID(ctx, tenantID, id)
}

func (s *Service) ListAssessments(ctx context.Context, tenantID string, filter AssessmentFilter) ([]AssessmentRecord, int, error) {
	if tenantID == "" {
		return nil, 0, fmt.Errorf("tenant ID is required")
	}
	return s.repo.List(ctx, tenantID, filter)
}

func (s *Service) CancelAssessment(ctx context.Context, tenantID, id string) error {
	if tenantID == "" || id == "" {
		return ErrAssessmentNotFound
	}

	detail, err := s.repo.GetByID(ctx, tenantID, id)
	if err != nil {
		return err
	}

	if detail.Status.IsTerminal() {
		return fmt.Errorf("%w: assessment is already in terminal state %s", ErrInvalidStateTransition, detail.Status)
	}

	if err := s.repo.UpdateStatus(ctx, tenantID, id, StatusCancelled, "Cancelled by user request"); err != nil {
		return err
	}

	if s.queue != nil {
		_ = s.queue.Cancel(ctx, id)
	}

	return nil
}

func (s *Service) GetProfiles(ctx context.Context, tenantID string) ([]ScanProfile, error) {
	return s.repo.GetProfiles(ctx, tenantID)
}

func (s *Service) GetTargets(ctx context.Context, tenantID string) ([]TargetOption, error) {
	return s.repo.GetTargets(ctx, tenantID)
}

// IsCanaryTargetAllowed evaluates target address against approved canary destinations.
func IsCanaryTargetAllowed(target string, allowed []string) bool {
	if strings.TrimSpace(target) == "" {
		return false
	}
	targetCandidate := strings.TrimSpace(target)
	if strings.Contains(targetCandidate, "://") {
		if u, err := url.Parse(targetCandidate); err == nil && u.Hostname() != "" {
			targetCandidate = u.Hostname()
		}
	} else if strings.Contains(targetCandidate, ":") {
		parts := strings.Split(targetCandidate, ":")
		targetCandidate = parts[0]
	}
	targetCandidate = strings.ToLower(targetCandidate)

	defaultCanaryHosts := []string{
		"scanner-mock.kelvin.internal",
		"mock-target.kelvin.internal",
		"localhost",
		"127.0.0.1",
	}

	for _, d := range defaultCanaryHosts {
		if targetCandidate == d || strings.HasSuffix(targetCandidate, "."+d) {
			return true
		}
	}

	for _, a := range allowed {
		a = strings.TrimSpace(strings.ToLower(a))
		if a == "" {
			continue
		}
		if strings.Contains(a, "://") {
			if au, err := url.Parse(a); err == nil && au.Hostname() != "" {
				a = au.Hostname()
			}
		} else if strings.Contains(a, ":") {
			parts := strings.Split(a, ":")
			a = parts[0]
		}
		if targetCandidate == a || strings.HasSuffix(targetCandidate, "."+a) {
			return true
		}
	}

	return false
}
