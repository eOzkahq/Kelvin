package normalization

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
)

var percentEncodingHex = regexp.MustCompile(`%[0-9a-fA-F]{2}`)

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

	validCVEs := make([]string, 0, len(cveIDs))
	for _, cve := range cveIDs {
		trimmed := strings.ToUpper(strings.TrimSpace(cve))
		if trimmed != "" {
			validCVEs = append(validCVEs, trimmed)
		}
	}
	if len(validCVEs) > 0 {
		sort.Strings(validCVEs)
		return validCVEs[0]
	}

	if cwe := strings.TrimSpace(cweID); cwe != "" {
		return strings.ToUpper(cwe)
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

// ComputeFingerprint computes the deterministic finding fingerprint (Algorithm v1).
func ComputeFingerprint(asset, endpoint, templateID string, cveIDs []string, cweID, title string) (string, string, error) {
	normAsset := NormalizeAsset(asset)
	if normAsset == "" {
		return "", "", fmt.Errorf("normalization: asset must not be empty")
	}

	normEndpoint, err := NormalizeEndpoint(endpoint)
	if err != nil {
		return "", "", err
	}

	vulnKey := DeriveVulnerabilityKey(templateID, cveIDs, cweID, title)
	if vulnKey == "" {
		return "", "", fmt.Errorf("normalization: could not derive vulnerability key")
	}

	canonical := fmt.Sprintf("v1\n%s\n%s\n%s", normAsset, normEndpoint, vulnKey)
	hash := sha256.Sum256([]byte(canonical))
	fingerprint := hex.EncodeToString(hash[:])

	return fingerprint, canonical, nil
}
