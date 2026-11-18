// Package redaction provides automated regex-based and schema-aware redaction
// of sensitive information in assessment evidence before persistence.
//
// See docs/security/DATA_LIFECYCLE.md §4 for the normative redaction rules.
package redaction

import (
	commonredact "github.com/kelvin/kelvin/packages/common/redaction"
)

// MaskedValue is the replacement text for redacted sensitive fields.
const MaskedValue = commonredact.MaskedValue

// MaxEvidenceBytesPerFinding defines the 64KiB ceiling on inline evidence.
const MaxEvidenceBytesPerFinding = commonredact.MaxEvidenceBytesPerFinding

// Redactor re-exports the common Redactor type.
type Redactor = commonredact.Redactor

// NewDefaultRedactor returns a Redactor with the default rule set (R1-R10).
func NewDefaultRedactor() *Redactor {
	return commonredact.NewDefaultRedactor()
}

// NewCustomRedactor returns a Redactor with the provided replacement regex patterns.
func NewCustomRedactor(patterns []string) (*Redactor, error) {
	return commonredact.NewCustomRedactor(patterns)
}

// RedactFinding redacts sensitive fields from a JSON byte slice.
func RedactFinding(data []byte) []byte {
	return commonredact.RedactRawJSON(data)
}
