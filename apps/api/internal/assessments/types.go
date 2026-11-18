package assessments

import (
	"errors"
	"time"
)

var (
	ErrInvalidTarget          = errors.New("assessments: invalid target address")
	ErrScopeNotConfirmed      = errors.New("assessments: authorized scope confirmation is required")
	ErrCanaryTargetProhibited = errors.New("assessments: target rejected by canary-only execution policy")
	ErrAssessmentNotFound     = errors.New("assessments: assessment not found")
	ErrInvalidProfile         = errors.New("assessments: invalid scan profile")
	ErrInvalidStateTransition = errors.New("assessments: invalid state transition")
)

type AssessmentStatus string

const (
	StatusQueued          AssessmentStatus = "QUEUED"
	StatusValidatingScope AssessmentStatus = "VALIDATING_SCOPE"
	StatusRunning         AssessmentStatus = "RUNNING"
	StatusCompleted       AssessmentStatus = "COMPLETED"
	StatusFailed          AssessmentStatus = "FAILED"
	StatusTimedOut        AssessmentStatus = "TIMED_OUT"
	StatusCancelled       AssessmentStatus = "CANCELLED"
)

func (s AssessmentStatus) IsValid() bool {
	switch s {
	case StatusQueued, StatusValidatingScope, StatusRunning, StatusCompleted, StatusFailed, StatusTimedOut, StatusCancelled:
		return true
	default:
		return false
	}
}

func (s AssessmentStatus) IsTerminal() bool {
	return s == StatusCompleted || s == StatusFailed || s == StatusTimedOut || s == StatusCancelled
}

type AssessmentStage string

const (
	StageQueued      AssessmentStage = "QUEUED"
	StagePreflight   AssessmentStage = "PREFLIGHT"
	StageDiscovery   AssessmentStage = "DISCOVERY"
	StageScanning    AssessmentStage = "SCANNING"
	StageVulnScan    AssessmentStage = "VULN_SCAN"
	StageNormalizing AssessmentStage = "NORMALIZING"
	StageReportGen   AssessmentStage = "REPORT_GEN"
	StageCompleted   AssessmentStage = "COMPLETED"
	StageCancelled   AssessmentStage = "CANCELLED"
	StageFailed      AssessmentStage = "FAILED"
)

type ScanProfile struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scanners    []string `json:"scanners"`
	RiskLevel   string   `json:"riskLevel"`
}

type TargetOption struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Address     string `json:"address"`
	Verified    bool   `json:"verified"`
	Environment string `json:"environment"`
}

type AssessmentRecord struct {
	ID            string           `json:"id"`
	TenantID      string           `json:"tenantId"`
	ProjectID     string           `json:"projectId,omitempty"`
	Name          string           `json:"name"`
	TargetID      string           `json:"targetId,omitempty"`
	TargetAddress string           `json:"targetAddress"`
	ProfileID     string           `json:"profileId"`
	ProfileName   string           `json:"profileName"`
	Status        AssessmentStatus `json:"status"`
	CriticalCount int              `json:"criticalCount"`
	HighCount     int              `json:"highCount"`
	TotalFindings int              `json:"totalFindings"`
	CreatedAt     time.Time        `json:"createdAt"`
	CompletedAt   *time.Time       `json:"completedAt,omitempty"`
	UpdatedAt     *time.Time       `json:"updatedAt,omitempty"`
}

type ScannerExecution struct {
	ID                 string     `json:"id"`
	Scanner            string     `json:"scanner"`
	Status             string     `json:"status"`
	FindingsCount      int        `json:"findingsCount"`
	FindingsDiscovered int        `json:"findingsDiscovered"`
	StartTime          *time.Time `json:"startTime,omitempty"`
	EndTime            *time.Time `json:"endTime,omitempty"`
	DurationSeconds    int        `json:"durationSeconds"`
	CurrentActivity    string     `json:"currentActivity,omitempty"`
	Error              string     `json:"error,omitempty"`
}

type AssessmentLog struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	Stage     string    `json:"stage,omitempty"`
}

type AssessmentTarget struct {
	ID       string `json:"id,omitempty"`
	Host     string `json:"host"`
	Name     string `json:"name,omitempty"`
	Verified bool   `json:"verified,omitempty"`
}

type AssessmentDetail struct {
	AssessmentRecord
	CurrentStage    AssessmentStage    `json:"currentStage"`
	Scanners        []ScannerExecution `json:"scanners"`
	Logs            []AssessmentLog    `json:"logs"`
	ErrorMessage    string             `json:"errorMessage,omitempty"`
	ProgressPercent int                `json:"progressPercent"`
	Targets         []AssessmentTarget `json:"targets,omitempty"`
}

type CreateAssessmentInput struct {
	Name                     string `json:"name"`
	TargetID                 string `json:"targetId,omitempty"`
	ProfileID                string `json:"profileId"`
	TargetAddress            string `json:"targetAddress,omitempty"`
	RateLimit                int    `json:"rateLimit,omitempty"`
	TimeoutMinutes           int    `json:"timeoutMinutes,omitempty"`
	AuthorizedScopeConfirmed bool   `json:"authorizedScopeConfirmed"`
	IdempotencyKey           string `json:"idempotencyKey,omitempty"`
	Targets                  []struct {
		Host string `json:"host"`
	} `json:"targets,omitempty"`
}

type AssessmentFilter struct {
	Status    string
	ProfileID string
	Search    string
	Limit     int
	Offset    int
}
