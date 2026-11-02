// Package evidence provides rule-versioned redaction, secret pattern detection,
// manual redaction overlays, and sanitized presentation envelopes for evidence.
//
// See docs/architecture/EVIDENCE_REDACTION_AND_SANITIZATION.md.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// RedactionRuleVersion identifies the active normative redaction ruleset.
const RedactionRuleVersion = "kelvin.redaction.v1"

// Replacement tokens providing technical context while concealing secrets.
const (
	MaskAuthToken    = "[REDACTED_AUTHORIZATION_TOKEN]"
	MaskCookie       = "[REDACTED_COOKIE]"
	MaskAPIKey       = "[REDACTED_API_KEY]"
	MaskPassword     = "[REDACTED_PASSWORD]"
	MaskPrivateKey   = "[REDACTED_PRIVATE_KEY]"
	MaskJWT          = "[REDACTED_JWT]"
	MaskManualSecret = "[REDACTED_MANUAL]"
)

var (
	// ErrUnauthorizedRawAccess is returned when an unprivileged caller attempts to read unredacted evidence.
	ErrUnauthorizedRawAccess = errors.New("evidence sanitization: unprivileged caller cannot access unredacted raw evidence")

	// ErrInvalidPattern is returned when a manual redaction pattern cannot be parsed.
	ErrInvalidPattern = errors.New("evidence sanitization: invalid manual redaction regex pattern")
)

// RedactionRule pairs a compiled regular expression with a contextual replacement token and category name.
type RedactionRule struct {
	Name        string
	Regex       *regexp.Regexp
	Replacement string
}

// SanitizerEngine executes pattern-based and manual secret redaction over evidence text.
type SanitizerEngine struct {
	rules []RedactionRule
}

// NewSanitizerEngine constructs the default versioned rules engine (kelvin.redaction.v1).
func NewSanitizerEngine() *SanitizerEngine {
	return &SanitizerEngine{
		rules: []RedactionRule{
			{
				Name:        "AUTHORIZATION_BEARER",
				Regex:       regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[^\s,;}]+`),
				Replacement: "$1" + MaskAuthToken,
			},
			{
				Name:        "AUTHORIZATION_BASIC",
				Regex:       regexp.MustCompile(`(?i)(authorization:\s*basic\s+)[^\s,;}]+`),
				Replacement: "$1" + MaskAuthToken,
			},
			{
				Name:        "AUTHORIZATION_GENERIC",
				Regex:       regexp.MustCompile(`(?i)(authorization:\s*)(?:token|key|digest)\s+[^\s,;}]+`),
				Replacement: "$1" + MaskAuthToken,
			},
			{
				Name:        "COOKIE_HEADER",
				Regex:       regexp.MustCompile(`(?i)(cookie:\s*[a-z0-9_-]+=)[^;,\s]+`),
				Replacement: "$1" + MaskCookie,
			},
			{
				Name:        "SET_COOKIE_HEADER",
				Regex:       regexp.MustCompile(`(?i)(set-cookie:\s*[a-z0-9_-]+=)[^;,\s]+`),
				Replacement: "$1" + MaskCookie,
			},
			{
				Name:        "PASSWORD_FIELD",
				Regex:       regexp.MustCompile(`(?i)([a-z_]*(?:password|passwd|pwd)[a-z_]*\s*[:=]\s*)[^&,;\s"}]+`),
				Replacement: "$1" + MaskPassword,
			},
			{
				Name:        "API_KEY_FIELD",
				Regex:       regexp.MustCompile(`(?i)([a-z_]*(?:api[_-]?key|secret[_-]?key|access[_-]?token)[a-z_]*\s*[:=]\s*)[^&,;\s"}]+`),
				Replacement: "$1" + MaskAPIKey,
			},
			{
				Name:        "JWT_TOKEN",
				Regex:       regexp.MustCompile(`eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`),
				Replacement: MaskJWT,
			},
			{
				Name:        "AWS_SECRET_KEY",
				Regex:       regexp.MustCompile(`(?i)(aws[_]?secret[_]?access[_]?key\s*[:=]\s*)[A-Za-z0-9/+=]{40}`),
				Replacement: "$1" + MaskAPIKey,
			},
			{
				Name:        "PEM_PRIVATE_KEY",
				Regex:       regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
				Replacement: MaskPrivateKey,
			},
		},
	}
}

// RedactText applies all automated pattern rules to the input text and tracks redacted categories.
func (e *SanitizerEngine) RedactText(input string) (string, []string) {
	output := input
	var appliedRules []string

	for _, rule := range e.rules {
		if rule.Regex.MatchString(output) {
			output = rule.Regex.ReplaceAllString(output, rule.Replacement)
			appliedRules = append(appliedRules, rule.Name)
		}
	}

	return output, appliedRules
}

// ApplyManualRedaction applies custom analyst-defined search patterns or literal strings.
func (e *SanitizerEngine) ApplyManualRedaction(input string, patterns []string) (string, error) {
	output := input
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return "", fmt.Errorf("%w: %q: %v", ErrInvalidPattern, p, err)
		}
		output = re.ReplaceAllString(output, MaskManualSecret)
	}
	return output, nil
}

// SanitizedEvidenceEnvelope provides safe, presentation-ready evidence for UI and report exports.
type SanitizedEvidenceEnvelope struct {
	EvidenceID       string          `json:"evidence_id"`
	TenantID         string          `json:"tenant_id"`
	OriginalSHA256   string          `json:"original_sha256"`
	SanitizedSHA256  string          `json:"sanitized_sha256"`
	RedactionStatus  RedactionStatus `json:"redaction_status"`
	RuleVersion      string          `json:"rule_version"`
	RedactedFields   []string        `json:"redacted_fields"`
	ContentType      string          `json:"content_type"`
	SanitizedContent string          `json:"sanitized_content"`
	IsUnredactedRaw  bool            `json:"is_unredacted_raw"`
	SanitizedAt      time.Time       `json:"sanitized_at"`
}

// ManualRedactionRequest carries analyst-submitted manual redaction rules.
type ManualRedactionRequest struct {
	TargetPatterns []string `json:"target_patterns"`
	Reason         string   `json:"reason"`
	AnalystID      string   `json:"analyst_id"`
}

// SanitizerService orchestrates evidence presentation sanitization for UI and export paths.
type SanitizerService struct {
	engine *SanitizerEngine
}

// NewSanitizerService creates a SanitizerService instance.
func NewSanitizerService() *SanitizerService {
	return &SanitizerService{
		engine: NewSanitizerEngine(),
	}
}

// PreparePresentationEnvelope transforms an EvidenceItem into a presentation envelope.
// If allowUnredacted is true and the caller is authorized, unredacted content is served.
// Otherwise, strict in-flight regex and token redaction is enforced.
func (s *SanitizerService) PreparePresentationEnvelope(
	item *EvidenceItem,
	allowUnredacted bool,
	manualRules *ManualRedactionRequest,
) (*SanitizedEvidenceEnvelope, error) {
	rawContent := item.InlineContent
	if rawContent == "" && item.StorageRef != "" {
		rawContent = fmt.Sprintf("[ARTIFACT_REFERENCE: %s]", item.StorageRef)
	}

	origHash := item.ChecksumSHA256
	if origHash == "" {
		h := sha256.Sum256([]byte(rawContent))
		origHash = hex.EncodeToString(h[:])
	}

	now := time.Now().UTC()

	// If unredacted access requested by authorized caller
	if allowUnredacted {
		return &SanitizedEvidenceEnvelope{
			EvidenceID:       item.ID,
			TenantID:         item.TenantID,
			OriginalSHA256:   origHash,
			SanitizedSHA256:  origHash,
			RedactionStatus:  RedactionUnredactedInternal,
			RuleVersion:      RedactionRuleVersion,
			RedactedFields:   item.RedactedFields,
			ContentType:      item.ContentType,
			SanitizedContent: rawContent,
			IsUnredactedRaw:  true,
			SanitizedAt:      now,
		}, nil
	}

	// Apply automated pattern redactions
	sanitizedText, detectedRules := s.engine.RedactText(rawContent)

	// Combine detected rules with existing item redacted fields
	allRedacted := make([]string, 0, len(item.RedactedFields)+len(detectedRules))
	allRedacted = append(allRedacted, item.RedactedFields...)
	for _, r := range detectedRules {
		found := false
		for _, existing := range allRedacted {
			if existing == r {
				found = true
				break
			}
		}
		if !found {
			allRedacted = append(allRedacted, r)
		}
	}

	// Apply manual analyst overlays if provided
	if manualRules != nil && len(manualRules.TargetPatterns) > 0 {
		var err error
		sanitizedText, err = s.engine.ApplyManualRedaction(sanitizedText, manualRules.TargetPatterns)
		if err != nil {
			return nil, err
		}
		allRedacted = append(allRedacted, "MANUAL_ANALYST_OVERLAY")
	}

	sanHashBytes := sha256.Sum256([]byte(sanitizedText))
	sanitizedSHA := hex.EncodeToString(sanHashBytes[:])

	status := RedactionSanitizedPresentation
	if len(allRedacted) == 0 {
		// Content was already clean
		status = RedactionSanitizedPresentation
	}

	return &SanitizedEvidenceEnvelope{
		EvidenceID:       item.ID,
		TenantID:         item.TenantID,
		OriginalSHA256:   origHash,
		SanitizedSHA256:  sanitizedSHA,
		RedactionStatus:  status,
		RuleVersion:      RedactionRuleVersion,
		RedactedFields:   allRedacted,
		ContentType:      item.ContentType,
		SanitizedContent: sanitizedText,
		IsUnredactedRaw:  false,
		SanitizedAt:      now,
	}, nil
}
