// Package manifest builds, validates, and stores immutable assessment execution manifests.
package manifest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// Version is the current schema version of the execution manifest.
	Version = "1.0"

	// RedactedValue is injected in place of sensitive configuration secrets.
	RedactedValue = "[REDACTED]"
)

var (
	ErrInvalidManifest    = errors.New("manifest: validation failed")
	ErrManifestExists     = errors.New("manifest: manifest already exists and is immutable")
	ErrManifestNotFound   = errors.New("manifest: manifest not found")
	ErrDigestMismatch     = errors.New("manifest: integrity digest mismatch")
	ErrMissingRequiredField = errors.New("manifest: missing required field")
)

// ScannerComponent describes the exact version and artifacts of a scanner tool.
type ScannerComponent struct {
	ScannerID      string `json:"scanner_id"`
	ScannerVersion string `json:"scanner_version"`
	AdapterVersion string `json:"adapter_version"`
	ImageDigest    string `json:"image_digest,omitempty"`
	RulesetCatalog string `json:"ruleset_catalog,omitempty"`
	RulesetDigest  string `json:"ruleset_digest,omitempty"`
}

// ResourceLimits specifies the execution bounds enforced on the assessment.
type ResourceLimits struct {
	HardDeadlineSeconds int64  `json:"hard_deadline_seconds"`
	MemoryLimit         string `json:"memory_limit,omitempty"`
	CPUQuota            string `json:"cpu_quota,omitempty"`
	RequestsPerSecond   int    `json:"requests_per_second,omitempty"`
}

// Manifest represents the complete, immutable execution manifest for an assessment run.
type Manifest struct {
	ManifestVersion string            `json:"manifest_version"`
	AssessmentID    string            `json:"assessment_id"`
	TenantID        string            `json:"tenant_id"`
	RunID           string            `json:"run_id"`
	ProfileID       string            `json:"profile_id"`
	ProfileVersion  string            `json:"profile_version"`
	Target          string            `json:"target"`
	StartedAt       time.Time         `json:"started_at"`
	Scanners        []ScannerComponent `json:"scanners"`
	ResourceLimits  ResourceLimits    `json:"resource_limits"`
	EffectiveConfig map[string]any    `json:"effective_config"`
	Digest          string            `json:"digest"`
}

// Builder constructs and calculates cryptographic digests for immutable manifests.
type Builder struct {
	manifest Manifest
}

// NewBuilder initializes a manifest builder with mandatory run coordinates.
func NewBuilder(tenantID, assessmentID, runID, target, profileID string) *Builder {
	return &Builder{
		manifest: Manifest{
			ManifestVersion: Version,
			TenantID:        strings.TrimSpace(tenantID),
			AssessmentID:    strings.TrimSpace(assessmentID),
			RunID:           strings.TrimSpace(runID),
			Target:          strings.TrimSpace(target),
			ProfileID:       strings.TrimSpace(profileID),
			ProfileVersion:  "1.0",
			StartedAt:       time.Now().UTC(),
			Scanners:        make([]ScannerComponent, 0),
			EffectiveConfig: make(map[string]any),
		},
	}
}

// SetProfileVersion sets the version of the scan profile.
func (b *Builder) SetProfileVersion(version string) *Builder {
	if strings.TrimSpace(version) != "" {
		b.manifest.ProfileVersion = strings.TrimSpace(version)
	}
	return b
}

// SetStartedAt sets the assessment execution start time.
func (b *Builder) SetStartedAt(t time.Time) *Builder {
	b.manifest.StartedAt = t.UTC()
	return b
}

// AddScanner adds a traceable scanner component specification.
func (b *Builder) AddScanner(s ScannerComponent) *Builder {
	b.manifest.Scanners = append(b.manifest.Scanners, s)
	return b
}

// SetResourceLimits specifies the active resource and deadline limits.
func (b *Builder) SetResourceLimits(limits ResourceLimits) *Builder {
	b.manifest.ResourceLimits = limits
	return b
}

// SetEffectiveConfig sets the active configuration, automatically redacting secrets.
func (b *Builder) SetEffectiveConfig(cfg map[string]any) *Builder {
	b.manifest.EffectiveConfig = RedactConfig(cfg)
	return b
}

// Build validates components and generates the cryptographic SHA-256 digest.
func (b *Builder) Build() (*Manifest, error) {
	m := b.manifest

	if err := Validate(&m); err != nil {
		return nil, err
	}

	digest, err := ComputeDigest(&m)
	if err != nil {
		return nil, fmt.Errorf("manifest: compute digest: %w", err)
	}
	m.Digest = digest

	return &m, nil
}

// Validate verifies that required coordinates and targets are well-formed.
func Validate(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("%w: manifest is nil", ErrInvalidManifest)
	}
	if m.ManifestVersion == "" {
		return fmt.Errorf("%w: manifest_version must not be empty", ErrMissingRequiredField)
	}
	if m.TenantID == "" {
		return fmt.Errorf("%w: tenant_id must not be empty", ErrMissingRequiredField)
	}
	if m.AssessmentID == "" {
		return fmt.Errorf("%w: assessment_id must not be empty", ErrMissingRequiredField)
	}
	if m.RunID == "" {
		return fmt.Errorf("%w: run_id must not be empty", ErrMissingRequiredField)
	}
	if m.ProfileID == "" {
		return fmt.Errorf("%w: profile_id must not be empty", ErrMissingRequiredField)
	}
	if m.Target == "" {
		return fmt.Errorf("%w: target must not be empty", ErrMissingRequiredField)
	}
	u, err := url.Parse(m.Target)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%w: target must be a valid absolute HTTP or HTTPS URL", ErrInvalidManifest)
	}
	if len(m.Scanners) == 0 {
		return fmt.Errorf("%w: at least one scanner component must be recorded", ErrInvalidManifest)
	}
	for i, s := range m.Scanners {
		if s.ScannerID == "" || s.ScannerVersion == "" || s.AdapterVersion == "" {
			return fmt.Errorf("%w: scanner %d must have scanner_id, scanner_version, and adapter_version", ErrInvalidManifest, i)
		}
	}
	return nil
}

// ComputeDigest produces a deterministic SHA-256 hash of canonical manifest fields.
func ComputeDigest(m *Manifest) (string, error) {
	// Copy manifest excluding the Digest field itself
	canonicalCopy := *m
	canonicalCopy.Digest = ""

	// Ensure scanners are sorted by ID for deterministic hashing
	sortedScanners := make([]ScannerComponent, len(canonicalCopy.Scanners))
	copy(sortedScanners, canonicalCopy.Scanners)
	sort.Slice(sortedScanners, func(i, j int) bool {
		return sortedScanners[i].ScannerID < sortedScanners[j].ScannerID
	})
	canonicalCopy.Scanners = sortedScanners

	raw, err := json.Marshal(canonicalCopy)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write(raw)
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyDigest verifies that the recorded Digest matches the computed hash.
func VerifyDigest(m *Manifest) (bool, error) {
	if m == nil || m.Digest == "" {
		return false, errors.New("manifest: digest is empty")
	}
	expected, err := ComputeDigest(m)
	if err != nil {
		return false, err
	}
	return m.Digest == expected, nil
}

// RedactConfig recursively redacts sensitive fields (passwords, tokens, keys).
func RedactConfig(cfg map[string]any) map[string]any {
	if cfg == nil {
		return make(map[string]any)
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		lowerKey := strings.ToLower(k)
		if isSensitiveKey(lowerKey) {
			out[k] = RedactedValue
			continue
		}
		switch val := v.(type) {
		case map[string]any:
			out[k] = RedactConfig(val)
		case []any:
			out[k] = redactSlice(val)
		default:
			out[k] = v
		}
	}
	return out
}

func redactSlice(s []any) []any {
	out := make([]any, len(s))
	for i, item := range s {
		if m, ok := item.(map[string]any); ok {
			out[i] = RedactConfig(m)
		} else {
			out[i] = item
		}
	}
	return out
}

func isSensitiveKey(k string) bool {
	sensitiveKeywords := []string{
		"password", "secret", "token", "api_key", "apikey",
		"authorization", "bearer", "credential", "private_key",
	}
	for _, kw := range sensitiveKeywords {
		if strings.Contains(k, kw) {
			return true
		}
	}
	return false
}

// Store provides persistence and integrity checking for immutable manifests.
type Store interface {
	Save(ctx context.Context, m *Manifest) error
	Get(ctx context.Context, tenantID, assessmentID, runID string) (*Manifest, error)
}

// MemoryStore provides a thread-safe in-memory store for unit tests and local execution.
type MemoryStore struct {
	mu        sync.RWMutex
	manifests map[string]*Manifest
}

// NewMemoryStore initializes an in-memory manifest store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		manifests: make(map[string]*Manifest),
	}
}

// Save stores the manifest, rejecting any attempt to overwrite or silently modify it.
func (s *MemoryStore) Save(ctx context.Context, m *Manifest) error {
	if err := Validate(m); err != nil {
		return err
	}
	valid, err := VerifyDigest(m)
	if err != nil || !valid {
		return ErrDigestMismatch
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := fmt.Sprintf("%s:%s:%s", m.TenantID, m.AssessmentID, m.RunID)
	if _, exists := s.manifests[key]; exists {
		return ErrManifestExists
	}

	// Deep copy to prevent caller mutation after storage
	raw, _ := json.Marshal(m)
	var copyM Manifest
	_ = json.Unmarshal(raw, &copyM)

	s.manifests[key] = &copyM
	return nil
}

// Get retrieves a manifest by its coordinates.
func (s *MemoryStore) Get(ctx context.Context, tenantID, assessmentID, runID string) (*Manifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fmt.Sprintf("%s:%s:%s", tenantID, assessmentID, runID)
	m, exists := s.manifests[key]
	if !exists {
		return nil, ErrManifestNotFound
	}

	raw, _ := json.Marshal(m)
	var copyM Manifest
	_ = json.Unmarshal(raw, &copyM)

	return &copyM, nil
}
