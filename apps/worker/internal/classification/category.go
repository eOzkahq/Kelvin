package classification

// FailureCategory represents the standardized classification taxonomy for scanner and execution failures.
type FailureCategory string

const (
	// CategoryInvalidConfig indicates invalid, unparsable, or disallowed scanner options.
	CategoryInvalidConfig FailureCategory = "ERR_INVALID_CONFIG"

	// CategoryUnsupportedVersion indicates scanner runtime binary or image compatibility mismatch.
	CategoryUnsupportedVersion FailureCategory = "ERR_UNSUPPORTED_VERSION"

	// CategoryTargetUnreachable indicates network connection refused, DNS failure, or target host down.
	CategoryTargetUnreachable FailureCategory = "ERR_TARGET_UNREACHABLE"

	// CategoryScopeViolation indicates target is out of scope or blocked by egress SSRF filter.
	CategoryScopeViolation FailureCategory = "ERR_SCOPE_VIOLATION"

	// CategoryProcessCrash indicates unexpected binary exit (SIGSEGV, panic, unhandled exception).
	CategoryProcessCrash FailureCategory = "ERR_PROCESS_CRASH"

	// CategoryTimeout indicates execution exceeded hard deadline or context cancellation.
	CategoryTimeout FailureCategory = "ERR_DEADLINE_EXCEEDED"

	// CategoryResourceExhaustion indicates OOM kill (exit 137) or container CPU throttling limit exceeded.
	CategoryResourceExhaustion FailureCategory = "ERR_RESOURCE_EXHAUSTION"

	// CategoryOutputParseError indicates scanner produced unparsable, corrupt, or truncated report JSON.
	CategoryOutputParseError FailureCategory = "ERR_OUTPUT_PARSE_ERROR"

	// CategoryInfrastructureFault indicates failure in worker daemon, container runtime, or workspace mount.
	CategoryInfrastructureFault FailureCategory = "ERR_INFRASTRUCTURE_FAULT"

	// CategoryUnknown indicates an unmapped, unexpected failure.
	CategoryUnknown FailureCategory = "ERR_UNKNOWN_FAILURE"
)

// AllCategories lists every supported standardized failure category.
var AllCategories = []FailureCategory{
	CategoryInvalidConfig,
	CategoryUnsupportedVersion,
	CategoryTargetUnreachable,
	CategoryScopeViolation,
	CategoryProcessCrash,
	CategoryTimeout,
	CategoryResourceExhaustion,
	CategoryOutputParseError,
	CategoryInfrastructureFault,
	CategoryUnknown,
}

// IsRetryable determines whether a failure category is inherently eligible for safe automated retry.
// Configuration errors, scope restrictions, and unsupported versions are strictly terminal.
func (c FailureCategory) IsRetryable() bool {
	switch c {
	case CategoryTargetUnreachable, CategoryTimeout, CategoryInfrastructureFault:
		return true
	case CategoryInvalidConfig, CategoryUnsupportedVersion, CategoryScopeViolation,
		CategoryResourceExhaustion, CategoryOutputParseError, CategoryProcessCrash, CategoryUnknown:
		return false
	default:
		return false
	}
}
