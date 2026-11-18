package normalization

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var (
	percentEncodingHex = regexp.MustCompile(`%[0-9a-fA-F]{2}`)
	taggedFPRegex      = regexp.MustCompile(`^fp_(v[0-9]+)_([0-9a-f]{64})$`)

	ErrEmptyAsset         = errors.New("normalization: asset must not be empty")
	ErrMissingVulnKey     = errors.New("normalization: could not derive vulnerability key")
	ErrInvalidTaggedFP    = errors.New("normalization: invalid tagged fingerprint format")
	ErrUnsupportedAlgo    = errors.New("normalization: unsupported fingerprint algorithm version")
)

const (
	AlgorithmV1      = "v1"
	AlgorithmV2      = "v2"
	DefaultAlgorithm = AlgorithmV1
)

// FingerprintInput encapsulates all identity factors required to generate a deterministic fingerprint.
// Volatile data (e.g. timestamps, transient request IDs, response payloads) are excluded by design.
type FingerprintInput struct {
	Asset      string
	Endpoint   string
	TemplateID string
	CVEIDs     []string
	CWEID      string
	Title      string
	Parameter  string
	Algorithm  string
}

// FingerprintResult encapsulates the generated digest, prefixed representation, and canonical string.
type FingerprintResult struct {
	Digest    string // 64-character lowercase hexadecimal SHA-256 (matches DB constraint ^[0-9a-f]{64}$)
	TaggedID  string // Prefixed identifier: fp_<version>_<digest>
	Canonical string // Normalized UTF-8 canonical string hashed to produce the digest
	Algorithm string // Algorithm version string ("v1", "v2")
}

// NormalizeCWE standardizes CWE identifiers to canonical "CWE-<number>" format.
func NormalizeCWE(cweID string) string {
	trimmed := strings.TrimSpace(cweID)
	if trimmed == "" {
		return ""
	}
	upper := strings.ToUpper(trimmed)
	if strings.HasPrefix(upper, "CWE-") {
		numPart := strings.TrimPrefix(upper, "CWE-")
		if _, err := strconv.Atoi(numPart); err == nil {
			return upper
		}
	} else if strings.HasPrefix(upper, "CWE_") {
		numPart := strings.TrimPrefix(upper, "CWE_")
		if _, err := strconv.Atoi(numPart); err == nil {
			return "CWE-" + numPart
		}
	} else if _, err := strconv.Atoi(upper); err == nil {
		return "CWE-" + upper
	}
	return upper
}

// NormalizeCVEs cleans, standardizes to "CVE-YYYY-NNNN", deduplicates, and sorts CVE IDs.
func NormalizeCVEs(cveIDs []string) []string {
	if len(cveIDs) == 0 {
		return []string{}
	}
	seen := make(map[string]bool)
	var result []string
	for _, raw := range cveIDs {
		trimmed := strings.ToUpper(strings.TrimSpace(raw))
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "CVE-") {
			if strings.HasPrefix(trimmed, "CVE_") {
				trimmed = "CVE-" + strings.TrimPrefix(trimmed, "CVE_")
			}
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			result = append(result, trimmed)
		}
	}
	sort.Strings(result)
	return result
}

// DeriveVulnerabilityKey derives the canonical vulnerability key according to FINDING_SCHEMA.md §5.3.
// Precedence:
// 1. vulnerability.template_id (lowercased, trimmed)
// 2. Lowest vulnerability.cve_ids entry (lexicographic sort of uppercase CVE IDs)
// 3. vulnerability.cwe_id (uppercase, trimmed)
// 4. Title slug (lowercase, non-alphanumeric runs replaced with '-', trimmed)
func DeriveVulnerabilityKey(templateID string, cveIDs []string, cweID string, title string) string {
	if tID := strings.TrimSpace(templateID); tID != "" {
		return strings.ToLower(tID)
	}

	validCVEs := NormalizeCVEs(cveIDs)
	if len(validCVEs) > 0 {
		return validCVEs[0]
	}

	if cwe := NormalizeCWE(cweID); cwe != "" {
		return cwe
	}

	return SlugifyTitle(title)
}

// SlugifyTitle turns a title into a canonical slug (FINDING_SCHEMA.md §5.3).
func SlugifyTitle(title string) string {
	lowered := strings.ToLower(title)
	var sb strings.Builder
	lastHyphen := true // prevents leading hyphen

	for _, r := range lowered {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
			lastHyphen = false
		} else {
			if !lastHyphen {
				sb.WriteByte('-')
				lastHyphen = true
			}
		}
	}

	res := sb.String()
	return strings.TrimRight(res, "-")
}

// NormalizeAsset normalizes the asset identifier (FINDING_SCHEMA.md §5.4).
func NormalizeAsset(asset string) string {
	trimmed := strings.TrimSpace(asset)
	if trimmed == "" {
		return ""
	}

	// If IP literal: canonicalize via RFC 5952
	if ip, err := netip.ParseAddr(trimmed); err == nil {
		return ip.String()
	}

	host := strings.ToLower(trimmed)
	return strings.TrimSuffix(host, ".")
}

// NormalizeEndpoint normalizes an endpoint URL (FINDING_SCHEMA.md §5.4).
func NormalizeEndpoint(rawEndpoint string) (string, error) {
	trimmed := strings.TrimSpace(rawEndpoint)
	if trimmed == "" || trimmed == "null" {
		return "", nil
	}

	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("normalization: invalid endpoint URL %q", trimmed)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("normalization: unsupported endpoint scheme %q", scheme)
	}

	rawHost := u.Hostname()
	normHost := NormalizeAsset(rawHost)
	if strings.Contains(normHost, ":") { // IPv6 literal
		normHost = "[" + normHost + "]"
	}

	port := u.Port()
	hostWithPort := normHost
	if port != "" {
		if !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
			hostWithPort = fmt.Sprintf("%s:%s", normHost, port)
		}
	}

	cleanPath := path.Clean(u.EscapedPath())
	if cleanPath == "" || cleanPath == "." {
		cleanPath = "/"
	}
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	// Uppercase percent-encoded hex sequences (%2f -> %2F)
	cleanPath = percentEncodingHex.ReplaceAllStringFunc(cleanPath, func(match string) string {
		return strings.ToUpper(match)
	})

	return fmt.Sprintf("%s://%s%s", scheme, hostWithPort, cleanPath), nil
}

// NormalizeParameter normalizes parameter / component identifiers (case-normalized, whitespace-trimmed).
func NormalizeParameter(param string) string {
	trimmed := strings.TrimSpace(param)
	if trimmed == "" {
		return ""
	}
	return strings.ToLower(trimmed)
}

// GenerateFingerprint produces a deterministic fingerprint from the provided identity inputs.
func GenerateFingerprint(in FingerprintInput) (*FingerprintResult, error) {
	normAsset := NormalizeAsset(in.Asset)
	if normAsset == "" {
		return nil, ErrEmptyAsset
	}

	normEndpoint, err := NormalizeEndpoint(in.Endpoint)
	if err != nil {
		return nil, err
	}

	vulnKey := DeriveVulnerabilityKey(in.TemplateID, in.CVEIDs, in.CWEID, in.Title)
	if vulnKey == "" {
		return nil, ErrMissingVulnKey
	}

	algo := in.Algorithm
	if algo == "" {
		algo = DefaultAlgorithm
	}

	var canonical string
	switch algo {
	case AlgorithmV1:
		// Algorithm v1 specification (FINDING_SCHEMA.md §5.5)
		canonical = fmt.Sprintf("v1\n%s\n%s\n%s", normAsset, normEndpoint, vulnKey)
	case AlgorithmV2:
		// Algorithm v2 specification: incorporates normalized parameter/component
		normParam := NormalizeParameter(in.Parameter)
		canonical = fmt.Sprintf("v2\n%s\n%s\n%s\n%s", normAsset, normEndpoint, vulnKey, normParam)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgo, algo)
	}

	hash := sha256.Sum256([]byte(canonical))
	digest := hex.EncodeToString(hash[:])
	taggedID := fmt.Sprintf("fp_%s_%s", algo, digest)

	return &FingerprintResult{
		Digest:    digest,
		TaggedID:  taggedID,
		Canonical: canonical,
		Algorithm: algo,
	}, nil
}

// ComputeFingerprint is the standard helper for Algorithm v1 (retains backward compatibility).
func ComputeFingerprint(asset, endpoint, templateID string, cveIDs []string, cweID, title string) (string, string, error) {
	res, err := GenerateFingerprint(FingerprintInput{
		Asset:      asset,
		Endpoint:   endpoint,
		TemplateID: templateID,
		CVEIDs:     cveIDs,
		CWEID:      cweID,
		Title:      title,
		Algorithm:  AlgorithmV1,
	})
	if err != nil {
		return "", "", err
	}
	return res.Digest, res.Canonical, nil
}

// ParseTaggedFingerprint parses a prefixed fingerprint (e.g. fp_v1_64hex) into its version and digest.
func ParseTaggedFingerprint(tagged string) (version string, digest string, err error) {
	matches := taggedFPRegex.FindStringSubmatch(strings.TrimSpace(tagged))
	if len(matches) != 3 {
		return "", "", ErrInvalidTaggedFP
	}
	return matches[1], matches[2], nil
}

// IsAmbiguousIdentity detects whether two findings share vulnerability and target asset
// but differ in parameter or endpoint specifics such that automatic merging would be ambiguous.
func IsAmbiguousIdentity(asset1, endpoint1, vulnKey1 string, asset2, endpoint2, vulnKey2 string) bool {
	if NormalizeAsset(asset1) != NormalizeAsset(asset2) {
		return false
	}
	if vulnKey1 != vulnKey2 {
		return false
	}
	// Same asset and vulnerability key, but different non-empty endpoints -> ambiguous match
	if endpoint1 != "" && endpoint2 != "" && endpoint1 != endpoint2 {
		return true
	}
	return false
}
