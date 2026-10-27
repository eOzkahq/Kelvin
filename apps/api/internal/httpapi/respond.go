package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	kelvinerrors "github.com/kelvin/kelvin/packages/common/errors"
	"github.com/kelvin/kelvin/packages/common/logging"
)

const (
	contentTypeJSON    = "application/json; charset=utf-8"
	contentTypeProblem = "application/problem+json; charset=utf-8"
)

// WriteSuccess serializes the standard success envelope (API_STANDARDS §6):
// {"success": true, "data": ..., "meta": ...}. Bare objects and bare arrays
// are never written.
func WriteSuccess(w http.ResponseWriter, r *http.Request, status int, data any, meta map[string]any) {
	envelope := map[string]any{"success": true, "data": data}
	if meta != nil {
		envelope["meta"] = meta
	}
	writeJSON(w, status, envelope)
}

// WriteProblem serializes an RFC 7807 problem (API_STANDARDS §7) with the
// mandatory correlation ID and timestamp (§10.1).
func WriteProblem(w http.ResponseWriter, r *http.Request, apiErr *kelvinerrors.API) {
	problem := apiErr.Problem(
		logging.CorrelationFromContext(r.Context()),
		r.URL.Path,
		time.Now().UTC().Format(time.RFC3339),
	)
	w.Header().Set("Content-Type", contentTypeProblem)
	if apiErr.Status == http.StatusServiceUnavailable || apiErr.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "30")
	}
	w.WriteHeader(apiErr.Status)
	_ = json.NewEncoder(w).Encode(problem)
}

// DecodeJSON strictly decodes an application/json request body into dst:
// unknown fields are rejected (422, §5.2), malformed JSON yields 400, and
// bodies over the gateway cap yield 413. On failure the problem response is
// already written and false is returned.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType := r.Header.Get("Content-Type")
	if mediaType != "" && !isJSONMediaType(mediaType) {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemUnsupportedMediaType,
			Title:  "Unsupported Media Type",
			Status: http.StatusUnsupportedMediaType,
			Detail: "Content-Type must be application/json.",
		})
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		WriteProblem(w, r, decodeError(err))
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		WriteProblem(w, r, &kelvinerrors.API{
			Type:   kelvinerrors.ProblemMalformedRequest,
			Title:  "Malformed Request",
			Status: http.StatusBadRequest,
			Detail: "Request body must contain a single JSON document.",
		})
		return false
	}
	return true
}

func decodeError(err error) *kelvinerrors.API {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return &kelvinerrors.API{
			Type:   kelvinerrors.ProblemPayloadTooLarge,
			Title:  "Payload Too Large",
			Status: http.StatusRequestEntityTooLarge,
			Detail: fmt.Sprintf("Request body exceeds the %d byte limit.", maxErr.Limit),
		}
	}
	var synErr *json.SyntaxError
	if errors.As(err, &synErr) {
		return &kelvinerrors.API{
			Type:   kelvinerrors.ProblemMalformedRequest,
			Title:  "Malformed Request",
			Status: http.StatusBadRequest,
			Detail: "Request body is not valid JSON.",
		}
	}
	if strings.HasPrefix(err.Error(), "json: unknown field ") {
		field := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   field,
			Code:    "unknown_field",
			Message: "field is not defined by this operation",
		}})
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		name := typeErr.Field
		if name == "" {
			name = "(body)"
		}
		return kelvinerrors.NewValidation([]kelvinerrors.FieldError{{
			Field:   name,
			Code:    "wrong_type",
			Message: fmt.Sprintf("expected %s", typeErr.Type.String()),
		}})
	}
	if errors.Is(err, io.EOF) {
		return &kelvinerrors.API{
			Type:   kelvinerrors.ProblemMalformedRequest,
			Title:  "Malformed Request",
			Status: http.StatusBadRequest,
			Detail: "Request body is required.",
		}
	}
	return &kelvinerrors.API{
		Type:   kelvinerrors.ProblemMalformedRequest,
		Title:  "Malformed Request",
		Status: http.StatusBadRequest,
		Detail: "Request body could not be decoded.",
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		fallback := fmt.Sprintf(
			`{"type":"urn:kelvin:problem:internal_error","title":"Internal Server Error","status":500,"detail":"An unexpected error occurred.","correlation_id":"","timestamp":%q}`,
			time.Now().UTC().Format(time.RFC3339),
		)
		w.Header().Set("Content-Type", contentTypeProblem)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(fallback))
		return
	}
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func isJSONMediaType(v string) bool {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	return v == "application/json" || strings.HasSuffix(v, "+json")
}
