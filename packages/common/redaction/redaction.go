// Package redaction provides automated regex-based and schema-aware redaction
// of sensitive information in assessment evidence before persistence.
//
// See docs/security/DATA_LIFECYCLE.md §4 for the normative redaction rules.
// Redaction is lossy by design: original unredacted sensitive values are never persisted.
package redaction

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	commonnorm "github.com/kelvin/kelvin/packages/common/normalization"
)

// MaskedValue is the replacement text for redacted sensitive fields.
const MaskedValue = "[REDACTED]"

// MaxEvidenceBytesPerFinding defines the 64KiB ceiling on inline evidence content.
const MaxEvidenceBytesPerFinding = 65536

// NamedRule pairs a category label with a compiled regex rule.
type NamedRule struct {
	Category string
	Pattern  *regexp.Regexp
}

// Redactor applies configurable redaction patterns to byte slices, strings, and evidence models.
type Redactor struct {
	namedRules []NamedRule
}

// NewDefaultRedactor returns a Redactor with the default normative rule set (R1-R10).
func NewDefaultRedactor() *Redactor {
	return &Redactor{
		namedRules: []NamedRule{
			// R1: Bearer token in Authorization header
			{Category: "authorization_bearer", Pattern: regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[^\s,;}]+`)},
			// R2: Basic auth in Authorization header
			{Category: "authorization_basic", Pattern: regexp.MustCompile(`(?i)(authorization:\s*basic\s+)[^\s,;}]+`)},
			// R3: Set-Cookie header values
			{Category: "set_cookie", Pattern: regexp.MustCompile(`(?i)(set-cookie:\s*[a-z][a-z0-9_-]*=)[^;,\s]+`)},
			// R4: Cookie header values
			{Category: "cookie", Pattern: regexp.MustCompile(`(?i)(cookie:\s*[a-z][a-z0-9_-]*=)[^;,\s]+`)},
			// R5: Password fields
			{Category: "password", Pattern: regexp.MustCompile(`(?i)([a-z_]*password[a-z_]*=)[^&,;\s"}]+`)},
			{Category: "password", Pattern: regexp.MustCompile(`(?i)([a-z_]*pass[a-z_]*=)[^&,;\s"}]+`)},
			{Category: "password", Pattern: regexp.MustCompile(`(?i)([a-z_]*pwd[a-z_]*=)[^&,;\s"}]+`)},
			// R6: Secret / API key / token fields
			{Category: "api_key", Pattern: regexp.MustCompile(`(?i)([a-z_]*api[_]?key[a-z_]*=)[^&,;\s"}]+`)},
			{Category: "secret", Pattern: regexp.MustCompile(`(?i)([a-z_]*secret[a-z_]*=)[^&,;\s"}]+`)},
			{Category: "token", Pattern: regexp.MustCompile(`(?i)([a-z_]*token[a-z_]*=)[^&,;\s"}]+`)},
			// R7: Generic Authorization header value
			{Category: "authorization", Pattern: regexp.MustCompile(`(?i)(authorization:\s*)[^\s,;}]+`)},
			// R8: JWT tokens (three base64url segments separated by dots)
			{Category: "jwt", Pattern: regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`)},
			// R9: AWS secret access keys (40 char base64)
			{Category: "aws_secret_key", Pattern: regexp.MustCompile(`(?i)(aws[_]?secret[_]?access[_]?key\s*[:=]\s*)[A-Za-z0-9/+=]{40}`)},
			// R10: PEM private key blocks
			{Category: "private_key", Pattern: regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)},
		},
	}
}

// NewCustomRedactor returns a Redactor with the provided replacement regex patterns.
func NewCustomRedactor(patterns []string) (*Redactor, error) {
	rules := make([]NamedRule, 0, len(patterns))
	for i, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		rules = append(rules, NamedRule{Category: fmt.Sprintf("custom_%d", i), Pattern: re})
	}
	return &Redactor{namedRules: rules}, nil
}

// RedactBytes applies all redaction rules to data, returning a scrubbed copy.
func (r *Redactor) RedactBytes(data []byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)
	for _, rule := range r.namedRules {
		result = rule.Pattern.ReplaceAll(result, []byte("$1"+MaskedValue))
	}
	return result
}

// RedactString applies all redaction rules to input string.
func (r *Redactor) RedactString(s string) string {
	return string(r.RedactBytes([]byte(s)))
}

// RedactEvidenceContent applies redaction to evidence text, returning the sanitized string
// and an array of detected sensitive category names.
func (r *Redactor) RedactEvidenceContent(content string) (string, []string) {
	if content == "" {
		return "", []string{}
	}

	sanitized := []byte(content)
	detected := make(map[string]bool)

	for _, rule := range r.namedRules {
		if rule.Pattern.Match(sanitized) {
			detected[rule.Category] = true
			sanitized = rule.Pattern.ReplaceAll(sanitized, []byte("$1"+MaskedValue))
		}
	}

	// Enforce 64KiB ceiling on inline evidence
	if len(sanitized) > MaxEvidenceBytesPerFinding {
		truncationNotice := []byte("\n[TRUNCATED: EXCEEDED 64KiB EVIDENCE CEILING]")
		keepLen := MaxEvidenceBytesPerFinding - len(truncationNotice)
		if keepLen < 0 {
			keepLen = 0
		}
		sanitized = append(sanitized[:keepLen], truncationNotice...)
		detected["truncated_oversized_evidence"] = true
	}

	fields := make([]string, 0, len(detected))
	for cat := range detected {
		fields = append(fields, cat)
	}
	sort.Strings(fields)

	return string(sanitized), fields
}

// RedactHeaders redacts sensitive values in an HTTP header map in place.
func (r *Redactor) RedactHeaders(h map[string][]string) {
	for name, values := range h {
		lower := strings.ToLower(name)
		switch lower {
		case "authorization":
			for i := range values {
				values[i] = MaskedValue
			}
		case "set-cookie", "cookie":
			for i, v := range values {
				values[i] = redactCookieValue(v)
			}
		default:
			for i, v := range values {
				values[i] = r.RedactString(v)
			}
		}
	}
}

func redactCookieValue(v string) string {
	eq := strings.IndexByte(v, '=')
	if eq < 0 {
		return MaskedValue
	}
	name := v[:eq+1]
	rest := v[eq+1:]
	semi := strings.IndexByte(rest, ';')
	if semi >= 0 {
		value := rest[:semi]
		attrs := rest[semi:]
		if len(value) > 0 {
			return name + MaskedValue + attrs
		}
		return name + attrs
	}
	if len(rest) > 0 {
		return name + MaskedValue
	}
	return name
}

// RedactFinding scrubs sensitive data across an entire CanonicalFinding model in place.
func (r *Redactor) RedactFinding(f *commonnorm.CanonicalFinding) {
	if f == nil {
		return
	}

	// 1. Redact reproduction steps
	for i := range f.ReproductionSteps {
		f.ReproductionSteps[i] = r.RedactString(f.ReproductionSteps[i])
	}

	// 2. Redact description if present
	if f.Description != "" {
		f.Description = r.RedactString(f.Description)
	}

	// 3. Redact and bound all evidence items
	for i := range f.Evidence {
		redacted, categories := r.RedactEvidenceContent(f.Evidence[i].ContentRedacted)
		f.Evidence[i].ContentRedacted = redacted

		// Merge existing redacted fields with newly detected categories
		fieldSet := make(map[string]bool)
		for _, rf := range f.Evidence[i].RedactedFields {
			trimmed := strings.TrimSpace(rf)
			if trimmed != "" {
				fieldSet[trimmed] = true
			}
		}
		for _, cat := range categories {
			fieldSet[cat] = true
		}

		mergedFields := make([]string, 0, len(fieldSet))
		for k := range fieldSet {
			mergedFields = append(mergedFields, k)
		}
		sort.Strings(mergedFields)
		f.Evidence[i].RedactedFields = mergedFields

		// Compute metrics and cryptographic checksum of redacted content
		f.Evidence[i].SizeBytes = int64(len(redacted))
		h := sha256.Sum256([]byte(redacted))
		f.Evidence[i].ChecksumSHA256 = hex.EncodeToString(h[:])
	}
}

// RedactRawJSON redacts sensitive fields from raw JSON bytes.
func RedactRawJSON(data []byte) []byte {
	red := NewDefaultRedactor()
	return red.RedactBytes(data)
}
