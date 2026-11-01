package classification

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	// Redaction patterns to sanitize sensitive credentials from error logs
	bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+[a-zA-Z0-9_\-\.]+`)
	secretPattern = regexp.MustCompile(`(?i)\b(token|password|secret|apikey|api_key)[=:\s]+[a-zA-Z0-9_\-\.\%]+`)
)

// RedactSecrets scrubs tokens, passwords, and API credentials from diagnostic error strings.
func RedactSecrets(s string) string {
	s = bearerPattern.ReplaceAllString(s, "Bearer [REDACTED]")
	s = secretPattern.ReplaceAllStringFunc(s, func(match string) string {
		parts := strings.SplitN(match, "=", 2)
		if len(parts) == 2 {
			return parts[0] + "=[REDACTED]"
		}
		parts = strings.SplitN(match, ":", 2)
		if len(parts) == 2 {
			return parts[0] + ": [REDACTED]"
		}
		return "[REDACTED]"
	})
	return s
}

// ClassifiedFailure encapsulates the normalized diagnostic outcome of a failed scanner run.
type ClassifiedFailure struct {
	Category      FailureCategory `json:"category"`
	Code          string          `json:"code"`
	Message       string          `json:"message"`
	ExitCode      int             `json:"exit_code"`
	Retryable     bool            `json:"retryable"`
	Scanner       string          `json:"scanner"`
	DiagnosticLog string          `json:"diagnostic_log,omitempty"`
}

// Error implements the standard error interface.
func (cf ClassifiedFailure) Error() string {
	return fmt.Sprintf("[%s/%s] %s (exit %d, retryable: %t)", cf.Category, cf.Code, cf.Message, cf.ExitCode, cf.Retryable)
}

// ClassificationInput provides context for classifying a scanner execution failure.
type ClassificationInput struct {
	Scanner       string
	ExitCode      int
	Stdout        string
	Stderr        string
	Err           error
	OOMKilled     bool
	TimedOut      bool
	EgressBlocked bool
}

// Classify inspects execution metadata, exit codes, and sanitized output to assign a standard failure category.
func Classify(ctx context.Context, in ClassificationInput) ClassifiedFailure {
	combinedErr := ""
	if in.Err != nil {
		combinedErr = in.Err.Error()
	}
	rawText := strings.TrimSpace(in.Stderr + " " + combinedErr + " " + in.Stdout)
	sanitizedText := RedactSecrets(rawText)

	// 1. Check Resource Exhaustion / OOM Kill (exit 137 or OOM flag)
	if in.OOMKilled || in.ExitCode == 137 || containsAny(sanitizedText, "out of memory", "oom-killer", "memory limit exceeded") {
		return ClassifiedFailure{
			Category:      CategoryResourceExhaustion,
			Code:          "ERR_OOM",
			Message:       "Scanner container was terminated by the OOM killer after exceeding assigned memory limit",
			ExitCode:      in.ExitCode,
			Retryable:     false,
			Scanner:       in.Scanner,
			DiagnosticLog: sanitizedText,
		}
	}

	// 2. Check Execution Timeout / Deadline Exceeded (exit 124 or context deadline)
	if in.TimedOut || in.ExitCode == 124 || errors.Is(in.Err, context.DeadlineExceeded) ||
		containsAny(sanitizedText, "deadline exceeded", "context deadline exceeded", "execution timed out", "signal: killed") {
		return ClassifiedFailure{
			Category:      CategoryTimeout,
			Code:          "ERR_DEADLINE_EXCEEDED",
			Message:       "Scanner process exceeded its assigned execution deadline and was safely aborted",
			ExitCode:      in.ExitCode,
			Retryable:     true,
			Scanner:       in.Scanner,
			DiagnosticLog: sanitizedText,
		}
	}

	// 3. Check Scope / Egress SSRF Restrictions
	if in.EgressBlocked || containsAny(sanitizedText, "X-Kelvin-Egress-Blocked", "egress: destination blocked", "forbidden target", "out of scope") {
		return ClassifiedFailure{
			Category:      CategoryScopeViolation,
			Code:          "ERR_SCOPE_BLOCKED",
			Message:       "Scanner attempted to connect to an out-of-scope, private, or metadata network destination",
			ExitCode:      in.ExitCode,
			Retryable:     false,
			Scanner:       in.Scanner,
			DiagnosticLog: sanitizedText,
		}
	}

	// 4. Check Invalid Configuration
	if containsAny(sanitizedText, "invalid scanner config", "unsupported option", "schema_version and scanner_id are required", "violates isolation profile", "unknown field") {
		return ClassifiedFailure{
			Category:      CategoryInvalidConfig,
			Code:          "ERR_INVALID_CONFIG",
			Message:       "Scanner configuration schema validation failed or violated security policy",
			ExitCode:      in.ExitCode,
			Retryable:     false,
			Scanner:       in.Scanner,
			DiagnosticLog: sanitizedText,
		}
	}

	// 5. Check Unsupported Scanner Version
	if containsAny(sanitizedText, "unsupported runtime version", "version mismatch", "incompatible scanner version", "binary not found") {
		return ClassifiedFailure{
			Category:      CategoryUnsupportedVersion,
			Code:          "ERR_VERSION_MISMATCH",
			Message:       "Scanner runtime binary version is unsupported or does not match verified catalog baseline",
			ExitCode:      in.ExitCode,
			Retryable:     false,
			Scanner:       in.Scanner,
			DiagnosticLog: sanitizedText,
		}
	}

	// 6. Check Target Unreachable / Network Connection Failures
	if containsAny(sanitizedText, "connection refused", "no such host", "name resolution", "no route to host", "network is unreachable", "i/o timeout", "tls handshake failure", "tls: handshake failure", "handshake failure", "connection reset by peer") {
		return ClassifiedFailure{
			Category:      CategoryTargetUnreachable,
			Code:          "ERR_TARGET_UNREACHABLE",
			Message:       "Target host could not be reached, DNS resolution failed, or connection was actively refused",
			ExitCode:      in.ExitCode,
			Retryable:     true,
			Scanner:       in.Scanner,
			DiagnosticLog: sanitizedText,
		}
	}

	// 7. Check Output Parsing Failure
	if containsAny(sanitizedText, "unexpected end of json", "unmarshal error", "invalid character", "failed to parse scanner output", "corrupt output file") {
		return ClassifiedFailure{
			Category:      CategoryOutputParseError,
			Code:          "ERR_REPORT_UNMARSHAL",
			Message:       "Scanner produced invalid, malformed, or corrupt JSON report artifacts",
			ExitCode:      in.ExitCode,
			Retryable:     false,
			Scanner:       in.Scanner,
			DiagnosticLog: sanitizedText,
		}
	}

	// 8. Check Process Crashes (non-zero exits)
	if in.ExitCode > 0 {
		return ClassifiedFailure{
			Category:      CategoryProcessCrash,
			Code:          fmt.Sprintf("ERR_PROCESS_EXIT_%d", in.ExitCode),
			Message:       fmt.Sprintf("Scanner process terminated abnormally with exit code %d", in.ExitCode),
			ExitCode:      in.ExitCode,
			Retryable:     false,
			Scanner:       in.Scanner,
			DiagnosticLog: sanitizedText,
		}
	}

	// 9. Unknown / Generic Fallback
	return ClassifiedFailure{
		Category:      CategoryUnknown,
		Code:          "ERR_GENERIC_FAILURE",
		Message:       "An unclassified failure occurred during scanner execution",
		ExitCode:      in.ExitCode,
		Retryable:     false,
		Scanner:       in.Scanner,
		DiagnosticLog: sanitizedText,
	}
}

func containsAny(s string, sub ...string) bool {
	lower := strings.ToLower(s)
	for _, subStr := range sub {
		if strings.Contains(lower, strings.ToLower(subStr)) {
			return true
		}
	}
	return false
}
