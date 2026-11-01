package progress

import (
	"context"
	"time"
)

// ScannerProgress models standardized progress emitted during scanner execution.
// It rigorously distinguishes between scanners that provide genuine completion
// metrics and those where percentage is unknown.
type ScannerProgress struct {
	// Percentage represents 0.0 - 100.0% completion. It is nil if the scanner
	// does not support or cannot reliably calculate completion percentage.
	// Kelvin never fabricates progress numbers.
	Percentage *float64 `json:"percentage,omitempty"`

	// ItemsCompleted is the number of discrete units processed (e.g., templates, hosts, checks).
	ItemsCompleted int64 `json:"items_completed,omitempty"`

	// ItemsTotal is the total number of discrete units scheduled to be processed, if known.
	ItemsTotal int64 `json:"items_total,omitempty"`

	// Units describes the discrete items (e.g., "templates", "requests", "ports").
	Units string `json:"units,omitempty"`

	// Message provides a brief, sanitized descriptive status message.
	Message string `json:"message,omitempty"`

	// UpdatedAt is the timestamp of the progress update.
	UpdatedAt time.Time `json:"updated_at"`
}

// HasPercentage returns true if the progress report contains an explicit percentage.
func (p ScannerProgress) HasPercentage() bool {
	return p.Percentage != nil
}

// NewIndeterminateProgress creates a progress report where the percentage is honestly unknown.
func NewIndeterminateProgress(message string) ScannerProgress {
	return ScannerProgress{
		Percentage: nil,
		Message:    SanitizeMessage(message),
		UpdatedAt:  time.Now().UTC(),
	}
}

// NewDeterminateProgress creates a progress report with known item counts and derived percentage.
func NewDeterminateProgress(completed, total int64, units, message string) ScannerProgress {
	var pctPtr *float64
	if total > 0 {
		pct := (float64(completed) / float64(total)) * 100.0
		if pct < 0.0 {
			pct = 0.0
		}
		if pct > 100.0 {
			pct = 100.0
		}
		pctPtr = &pct
	}
	return ScannerProgress{
		Percentage:     pctPtr,
		ItemsCompleted: completed,
		ItemsTotal:     total,
		Units:          units,
		Message:        SanitizeMessage(message),
		UpdatedAt:      time.Now().UTC(),
	}
}

// NewPercentageProgress creates a progress report with an explicit percentage.
func NewPercentageProgress(pct float64, message string) ScannerProgress {
	if pct < 0.0 {
		pct = 0.0
	}
	if pct > 100.0 {
		pct = 100.0
	}
	return ScannerProgress{
		Percentage: &pct,
		Message:    SanitizeMessage(message),
		UpdatedAt:  time.Now().UTC(),
	}
}

// ProgressReporter is implemented by listeners that accept runtime scanner progress updates.
type ProgressReporter interface {
	ReportProgress(ctx context.Context, progress ScannerProgress) error
}

type progressContextKey struct{}

// WithReporter binds a ProgressReporter into a Go context.
func WithReporter(ctx context.Context, reporter ProgressReporter) context.Context {
	if reporter == nil {
		return ctx
	}
	return context.WithValue(ctx, progressContextKey{}, reporter)
}

// ReporterFromContext extracts a ProgressReporter from a Go context if present.
func ReporterFromContext(ctx context.Context) (ProgressReporter, bool) {
	if ctx == nil {
		return nil, false
	}
	reporter, ok := ctx.Value(progressContextKey{}).(ProgressReporter)
	return reporter, ok
}
