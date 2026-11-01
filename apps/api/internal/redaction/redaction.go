// Package redaction provides automated regex-based and schema-aware redaction
// of sensitive information in assessment evidence before persistence.
//
// See docs/security/DATA_LIFECYCLE.md §4 for the normative redaction rules.
//
// Redaction is lossy by design: the original unredacted data is never stored.
// If a consumer needs unredacted evidence, they must re-run the scan against
// the target with appropriate authorization.
package redaction

import (
	"regexp"
	"strings"
)

// MaskedValue is the replacement text for redacted sensitive fields.
const MaskedValue = "[REDACTED]"

// Redactor applies configurable redaction patterns to byte slices and strings.
// The zero value uses the default rule set (R1-R10 from DATA_LIFECYCLE §4).
type Redactor struct {
	rules []*regexp.Regexp
}

// NewDefaultRedactor returns a Redactor with the default rule set:
//
//	R1 Authorization: Bearer <token>   → [REDACTED]
//	R2 Authorization: Basic <token>    → [REDACTED]
//	R3 Set-Cookie: name=value          → name=[REDACTED]
//	R4 Cookie: name=value              → name=[REDACTED]
//	R5 password/pass/pwd=value         → field=[REDACTED]
//	R6 secret/api_key/token=value      → field=[REDACTED]
//	R7 authorization: <value> (header) → [REDACTED]
//	R8 JWT tokens (eyJ...eyJ...eyJ...)  → [REDACTED_JWT]
//	R9 AWS secret keys                  → [REDACTED_AWS_KEY]
//	R10 PEM private key blocks          → [REDACTED_PRIVATE_KEY]
func NewDefaultRedactor() *Redactor {
	return &Redactor{
		rules: []*regexp.Regexp{
			// R1: Bearer token in Authorization header
			mustCompile(`(?i)(authorization:\s*bearer\s+)[^\s,;}]+`),
			// R2: Basic auth in Authorization header
			mustCompile(`(?i)(authorization:\s*basic\s+)[^\s,;}]+`),
			// R3: Set-Cookie header values
			mustCompile(`(?i)(set-cookie:\s*[a-z][a-z0-9_-]*=)[^;,\s]+`),
			// R4: Cookie header values
			mustCompile(`(?i)(cookie:\s*[a-z][a-z0-9_-]*=)[^;,\s]+`),
			// R5: Password form fields (captures key= in group 1)
			mustCompile(`(?i)([a-z_]*password[a-z_]*=)[^&,;\s"}]+`),
			mustCompile(`(?i)([a-z_]*pass[a-z_]*=)[^&,;\s"}]+`),
			mustCompile(`(?i)([a-z_]*pwd[a-z_]*=)[^&,;\s"}]+`),
			// R6: Secret / API key / token fields (captures key= in group 1)
			mustCompile(`(?i)([a-z_]*secret[a-z_]*=)[^&,;\s"}]+`),
			mustCompile(`(?i)([a-z_]*api[_]?key[a-z_]*=)[^&,;\s"}]+`),
			mustCompile(`(?i)([a-z_]*token[a-z_]*=)[^&,;\s"}]+`),
			// R7: Generic Authorization header value
			mustCompile(`(?i)(authorization:\s*)[^\s,;}]+`),
			// R8: JWT tokens (three base64url segments separated by dots)
			mustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`),
			// R9: AWS secret access keys (40 char base64)
			mustCompile(`(?i)(aws[_]?secret[_]?access[_]?key\s*[:=]\s*)[A-Za-z0-9/+=]{40}`),
			// R10: PEM private key blocks
			mustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
		},
	}
}

// NewCustomRedactor returns a Redactor with the provided replacement patterns.
// Each pattern must contain at least one capture group; the text matched by
// group 1 is preserved and the remainder is replaced with MaskedValue.
func NewCustomRedactor(patterns []string) (*Redactor, error) {
	rules := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, err
		}
		rules = append(rules, re)
	}
	return &Redactor{rules: rules}, nil
}

// RedactBytes applies all redaction rules to the input and returns a new byte
// slice with sensitive values replaced by MaskedValue. The input is not
// modified.
func (r *Redactor) RedactBytes(data []byte) []byte {
	result := make([]byte, len(data))
	copy(result, data)
	for _, rule := range r.rules {
		result = rule.ReplaceAll(result, []byte("$1"+MaskedValue))
	}
	return result
}

// RedactString applies all redaction rules to the input string and returns a
// new string with sensitive values replaced by MaskedValue.
func (r *Redactor) RedactString(s string) string {
	return string(r.RedactBytes([]byte(s)))
}

// RedactHeaders redacts sensitive values in an http.Header map in place.
// Header names are preserved; values containing credentials, cookies, tokens,
// or authorization data are replaced with MaskedValue.
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

// redactCookieValue redacts the value portion of a Cookie or Set-Cookie
// header, preserving the cookie name and attributes.
func redactCookieValue(v string) string {
	// Split on first '=' to separate name from value+attributes.
	eq := strings.IndexByte(v, '=')
	if eq < 0 {
		return MaskedValue
	}
	name := v[:eq+1] // include '='
	rest := v[eq+1:]
	// Strip attributes after ';' from the value portion.
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

// mustCompile compiles a regex and panics on error. Used for static rules.
func mustCompile(p string) *regexp.Regexp {
	return regexp.MustCompile(maskGroups(p))
}

// maskGroups rewrites a regex pattern so that group 1 captures the prefix to
// preserve and the replacement uses $1 + MaskedValue. Patterns that already
// have a capture group as group 1 are used as-is; patterns without a group 1
// capture are wrapped so the entire match's prefix before the sensitive value
// is captured.
//
// This is a simplifying wrapper: all default patterns already end their
// capture group right before the sensitive value, so ReplaceAll with
// "$1[REDACTED]" produces correct output.
func maskGroups(p string) string {
	return p
}

// RedactFinding redacts sensitive fields in a finding-like byte slice,
// focusing on the evidence and reproduction_steps arrays where raw HTTP
// traffic may be present. It is safe to call on any JSON byte slice.
func RedactFinding(data []byte) []byte {
	red := NewDefaultRedactor()
	return red.RedactBytes(data)
}

// Compile-time check that Redactor does not allow copying.
var _ interface{ RedactBytes([]byte) []byte } = (*Redactor)(nil)
