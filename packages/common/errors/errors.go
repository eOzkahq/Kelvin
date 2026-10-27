// Package errors defines the canonical Kelvin API error vocabulary
// (API_STANDARDS.md §12.2). Every non-2xx response the control plane emits is
// built from one of these constructors, which keeps the RFC 7807 problem
// registry (§7.2) enforced in code rather than by convention.
package errors

// FieldError is one entry of the RFC 7807 errors[] array; shape locked by
// packages/schemas/api-error.schema.json.
type FieldError struct {
	Field         string   `json:"field"`
	Code          string   `json:"code"`
	Message       string   `json:"message"`
	AllowedValues []string `json:"allowed_values,omitempty"`
}

// API is a safe, serializable API error. The underlying cause of an internal
// error is deliberately unexported: it can be unwrapped for logging, but it can
// never be marshalled into a response body (API_STANDARDS §7.3).
type API struct {
	Type   string
	Title  string
	Status int
	Detail string
	Fields []FieldError
	cause  error
}

// Problem is the wire form of an API error, matching api-error.schema.json.
type Problem struct {
	Type          string       `json:"type"`
	Title         string       `json:"title"`
	Status        int          `json:"status"`
	Detail        string       `json:"detail,omitempty"`
	Instance      string       `json:"instance,omitempty"`
	CorrelationID string       `json:"correlation_id"`
	Timestamp     string       `json:"timestamp"`
	Errors        []FieldError `json:"errors,omitempty"`
	RetryAfter    *int         `json:"retry_after_seconds,omitempty"`
}

const (
	ProblemValidationFailed     = "urn:kelvin:problem:validation_failed"
	ProblemNotFound             = "urn:kelvin:problem:not_found"
	ProblemForbidden            = "urn:kelvin:problem:forbidden"
	ProblemConflict             = "urn:kelvin:problem:conflict"
	ProblemTargetScopeViolation = "urn:kelvin:problem:target_scope_violation"
	ProblemInternalError        = "urn:kelvin:problem:internal_error"
	ProblemUnauthenticated      = "urn:kelvin:problem:unauthenticated"
	ProblemMalformedRequest     = "urn:kelvin:problem:malformed_request"
	ProblemUnsupportedMediaType = "urn:kelvin:problem:unsupported_media_type"
	ProblemPayloadTooLarge      = "urn:kelvin:problem:payload_too_large"
	ProblemRateLimited          = "urn:kelvin:problem:rate_limited"
	ProblemMethodNotAllowed     = "urn:kelvin:problem:method_not_allowed"
	ProblemServiceUnavailable   = "urn:kelvin:problem:service_unavailable"
	titleValidationFailed       = "Validation Failed"
	titleNotFound               = "Resource Not Found"
	titleForbidden              = "Forbidden"
	titleConflict               = "Conflict"
	titleTargetScopeViolation   = "Target Scope Violation"
	titleInternalError          = "Internal Server Error"
	titleMalformedRequest       = "Malformed Request"
	titleUnsupportedMediaType   = "Unsupported Media Type"
	titlePayloadTooLarge        = "Payload Too Large"
	titleMethodNotAllowed       = "Method Not Allowed"
	genericInternalDetail       = "An unexpected error occurred. The correlation ID can be used with support to locate details."
)

// NewValidation builds 422 validation_failed with field-level errors.
func NewValidation(fields []FieldError) *API {
	return &API{
		Type:   ProblemValidationFailed,
		Title:  titleValidationFailed,
		Status: 422,
		Fields: fields,
	}
}

// NewNotFound builds 404 not_found. Used both for unknown IDs and for
// cross-tenant resources (indistinguishable by design, T-08).
func NewNotFound(detail string) *API {
	return &API{Type: ProblemNotFound, Title: titleNotFound, Status: 404, Detail: detail}
}

// NewForbidden builds 403 forbidden (authenticated, permission denied).
func NewForbidden(detail string) *API {
	return &API{Type: ProblemForbidden, Title: titleForbidden, Status: 403, Detail: detail}
}

// NewConflict builds 409 conflict (illegal state transition, duplicate, idempotency mismatch).
func NewConflict(detail string) *API {
	return &API{Type: ProblemConflict, Title: titleConflict, Status: 409, Detail: detail}
}

// NewTargetScopeViolation builds 422 target_scope_violation (blocked target class).
func NewTargetScopeViolation(detail string) *API {
	return &API{Type: ProblemTargetScopeViolation, Title: titleTargetScopeViolation, Status: 422, Detail: detail}
}

// NewInternal builds 500 internal_error. The cause is retained for logging
// only and is never exposed to clients.
func NewInternal(err error) *API {
	return &API{Type: ProblemInternalError, Title: titleInternalError, Status: 500, Detail: genericInternalDetail, cause: err}
}

// Unwrap exposes the internal cause to the errors/unwrap chain for logging.
func (a *API) Unwrap() error { return a.cause }

// Error renders a safe summary (type + title only); the internal cause is
// never part of the string that logging or a response serializer can reach.
func (a *API) Error() string { return a.Title + " (" + a.Type + ")" }

// Problem renders the RFC 7807 body with the mandatory correlation ID and timestamp.
func (a *API) Problem(correlationID, instance, timestamp string) Problem {
	p := Problem{
		Type:          a.Type,
		Title:         a.Title,
		Status:        a.Status,
		Detail:        a.Detail,
		Instance:      instance,
		CorrelationID: correlationID,
		Timestamp:     timestamp,
		Errors:        a.Fields,
	}
	return p
}
