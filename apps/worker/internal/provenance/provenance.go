// Package provenance tracks, records, and redacts scanner execution provenance
// and runtime diagnostic events.
package provenance

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"go.uber.org/zap"
)

const (
	// RedactedMarker replaces sensitive arguments and environment variables.
	RedactedMarker = "[REDACTED]"
)

var (
	sensitiveArgRegex = regexp.MustCompile(`(?i)(api[_-]?key|token|secret|password|bearer|auth[_-]?header|credential)[=:\s]+([^\s]+)`)
	sensitiveFlagPrefixes = []string{
		"-h", "-H", "--header", "-header", "--auth", "-auth", "--token", "-token", "--key", "-key",
	}
)

// DiagnosticEvent represents an operational execution event.
type DiagnosticEvent struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"` // "info", "warning", "error"
	Stage     string         `json:"stage"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// ExecutionProvenance captures complete runtime provenance for an individual scanner invocation.
type ExecutionProvenance struct {
	AssessmentID          string            `json:"assessment_id"`
	TenantID              string            `json:"tenant_id"`
	RunID                 string            `json:"run_id"`
	ScannerID             string            `json:"scanner_id"`
	CorrelationID         string            `json:"correlation_id,omitempty"`
	ImageReference        string            `json:"image_reference,omitempty"`
	ImageDigest           string            `json:"image_digest,omitempty"`
	TemplateCatalogDigest string            `json:"template_catalog_digest,omitempty"`
	Attempt               int               `json:"attempt"`
	CommandLine           []string          `json:"command_line"`
	Environment           []string          `json:"environment"`
	StartedAt             time.Time         `json:"started_at"`
	CompletedAt           time.Time         `json:"completed_at"`
	DurationMS            int64             `json:"duration_ms"`
	ExitCode              int               `json:"exit_code"`
	PeakMemoryBytes       int64             `json:"peak_memory_bytes,omitempty"`
	CPUUsageUserMS        int64             `json:"cpu_usage_user_ms,omitempty"`
	CPUUsageSysMS         int64             `json:"cpu_usage_sys_ms,omitempty"`
	NetworkTxBytes        int64             `json:"network_tx_bytes,omitempty"`
	NetworkRxBytes        int64             `json:"network_rx_bytes,omitempty"`
	Diagnostics           []DiagnosticEvent `json:"diagnostics"`
}

// Collector records, redacts, and exports provenance and operational diagnostics.
type Collector struct {
	mu         sync.Mutex
	provenance ExecutionProvenance
	logger     *zap.Logger
}

// NewCollector initializes a provenance collector for a scanner run.
func NewCollector(tenantID, assessmentID, runID, scannerID, correlationID string, attempt int, logger *zap.Logger) *Collector {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &Collector{
		logger: logger,
		provenance: ExecutionProvenance{
			TenantID:      tenantID,
			AssessmentID:  assessmentID,
			RunID:         runID,
			ScannerID:     scannerID,
			CorrelationID: correlationID,
			Attempt:       attempt,
			CommandLine:   make([]string, 0),
			Environment:   make([]string, 0),
			Diagnostics:   make([]DiagnosticEvent, 0),
		},
	}
}

// RecordImageMetadata stores immutable image and catalog digest information in provenance.
func (c *Collector) RecordImageMetadata(ref, digest, catalogDigest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.provenance.ImageReference = ref
	c.provenance.ImageDigest = digest
	c.provenance.TemplateCatalogDigest = catalogDigest
}

// RecordStart marks execution start, redacting sensitive command line flags and environment variables.
func (c *Collector) RecordStart(cmdLine []string, env []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.provenance.StartedAt = time.Now().UTC()
	c.provenance.CommandLine = RedactCommandLine(cmdLine)
	c.provenance.Environment = RedactEnvironment(env)

	c.logger.Info("scanner execution started",
		zap.String("tenant_id", c.provenance.TenantID),
		zap.String("assessment_id", c.provenance.AssessmentID),
		zap.String("run_id", c.provenance.RunID),
		zap.String("scanner_id", c.provenance.ScannerID),
		zap.String("correlation_id", c.provenance.CorrelationID),
		zap.Int("attempt", c.provenance.Attempt),
		zap.Strings("command_line", c.provenance.CommandLine),
		zap.Time("started_at", c.provenance.StartedAt),
	)
}

// RecordDiagnostic logs and appends an operational diagnostic event.
func (c *Collector) RecordDiagnostic(level, stage, code, message string, meta map[string]any) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cleanMsg := RedactString(message)
	evt := DiagnosticEvent{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Stage:     stage,
		Code:      code,
		Message:   cleanMsg,
		Metadata:  meta,
	}
	c.provenance.Diagnostics = append(c.provenance.Diagnostics, evt)

	fields := []zap.Field{
		zap.String("tenant_id", c.provenance.TenantID),
		zap.String("assessment_id", c.provenance.AssessmentID),
		zap.String("run_id", c.provenance.RunID),
		zap.String("scanner_id", c.provenance.ScannerID),
		zap.String("stage", stage),
		zap.String("code", code),
	}
	for k, v := range meta {
		fields = append(fields, zap.Any("meta_"+k, v))
	}

	switch level {
	case "error":
		c.logger.Error(cleanMsg, fields...)
	case "warning":
		c.logger.Warn(cleanMsg, fields...)
	default:
		c.logger.Info(cleanMsg, fields...)
	}
}

// RecordCompletion records completion coordinates and resource statistics.
func (c *Collector) RecordCompletion(exitCode int, duration time.Duration, peakMemory, txBytes, rxBytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.provenance.CompletedAt = time.Now().UTC()
	c.provenance.DurationMS = duration.Milliseconds()
	c.provenance.ExitCode = exitCode
	c.provenance.PeakMemoryBytes = peakMemory
	c.provenance.NetworkTxBytes = txBytes
	c.provenance.NetworkRxBytes = rxBytes

	c.logger.Info("scanner execution completed",
		zap.String("tenant_id", c.provenance.TenantID),
		zap.String("assessment_id", c.provenance.AssessmentID),
		zap.String("run_id", c.provenance.RunID),
		zap.String("scanner_id", c.provenance.ScannerID),
		zap.Int("exit_code", exitCode),
		zap.Int64("duration_ms", c.provenance.DurationMS),
		zap.Int64("peak_memory_bytes", peakMemory),
		zap.Int64("network_tx_bytes", txBytes),
		zap.Int64("network_rx_bytes", rxBytes),
	)
}

// Provenance returns a snapshot copy of the execution provenance record.
func (c *Collector) Provenance() ExecutionProvenance {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := c.provenance
	out.CommandLine = make([]string, len(c.provenance.CommandLine))
	copy(out.CommandLine, c.provenance.CommandLine)
	out.Environment = make([]string, len(c.provenance.Environment))
	copy(out.Environment, c.provenance.Environment)
	out.Diagnostics = make([]DiagnosticEvent, len(c.provenance.Diagnostics))
	copy(out.Diagnostics, c.provenance.Diagnostics)
	return out
}

// ToExecutionDiagnostics converts operational diagnostics to canonical adapters.ExecutionDiagnostic.
func (c *Collector) ToExecutionDiagnostics() []adapters.ExecutionDiagnostic {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := make([]adapters.ExecutionDiagnostic, 0, len(c.provenance.Diagnostics))
	for _, d := range c.provenance.Diagnostics {
		out = append(out, adapters.ExecutionDiagnostic{
			Level:   d.Level,
			Code:    d.Code,
			Message: d.Message,
		})
	}
	return out
}

// RedactCommandLine sanitizes command line arguments.
func RedactCommandLine(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	redacted := make([]string, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if isSensitiveFlag(arg) && i+1 < len(args) {
			redacted[i] = arg
			redacted[i+1] = RedactedMarker
			i++
			continue
		}
		redacted[i] = RedactString(arg)
	}
	return redacted
}

// RedactEnvironment sanitizes environment variables.
func RedactEnvironment(env []string) []string {
	if len(env) == 0 {
		return nil
	}
	redacted := make([]string, len(env))
	for i, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			key, val := parts[0], parts[1]
			if isSensitiveKey(key) {
				redacted[i] = fmt.Sprintf("%s=%s", key, RedactedMarker)
				continue
			}
			redacted[i] = fmt.Sprintf("%s=%s", key, RedactString(val))
		} else {
			redacted[i] = RedactString(entry)
		}
	}
	return redacted
}

// RedactString scrubs embedded tokens, passwords, and bearer credentials.
func RedactString(s string) string {
	s = sensitiveArgRegex.ReplaceAllString(s, "$1="+RedactedMarker)
	if strings.Contains(strings.ToLower(s), "bearer ") {
		re := regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9_\-\.]+)`)
		s = re.ReplaceAllString(s, "Bearer "+RedactedMarker)
	}
	return s
}

func isSensitiveFlag(flag string) bool {
	lower := strings.ToLower(flag)
	for _, p := range sensitiveFlagPrefixes {
		if lower == p || strings.HasPrefix(lower, p+"=") {
			return true
		}
	}
	return false
}

func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	sensitiveKeywords := []string{
		"token", "secret", "password", "key", "auth", "bearer", "cred", "private",
	}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
