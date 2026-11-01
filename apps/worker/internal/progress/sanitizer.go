package progress

import (
	"regexp"
	"strings"
)

var (
	// Redact basic auth in URLs: http(s)://user:password@host
	basicAuthRe = regexp.MustCompile(`(?i)(https?://[^:@/ \t\r\n]+):([^@/ \t\r\n]+)@`)

	// Redact query parameter secrets: (?i)(token|password|passwd|secret|api_key|apikey|auth|key|access_token|client_secret)=...
	querySecretRe = regexp.MustCompile(`(?i)(password|passwd|pass|secret|api_key|apikey|token|access_token|auth|key|client_secret)=([^& \t\r\n)"']+)`)

	// Redact Bearer tokens in headers or strings
	bearerRe = regexp.MustCompile(`(?i)Bearer\s+([A-Za-z0-9\-._~+/]+=*)`)

	// Redact Authorization headers or cookies
	headerSecretRe = regexp.MustCompile(`(?i)(Authorization|X-Api-Key|X-Auth-Token|Cookie|Set-Cookie):\s*([^\r\n]+)`)

	// Strip ANSI terminal escape sequences
	ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")
)

const maxMessageLength = 256

// SanitizeMessage removes sensitive scanner details, auth headers, credentials,
// and bounds string length to prevent leaking secrets into progress streams.
func SanitizeMessage(msg string) string {
	if msg == "" {
		return ""
	}

	// 1. Strip ANSI escape sequences
	cleaned := ansiRe.ReplaceAllString(msg, "")

	// 2. Redact basic auth in URLs
	cleaned = basicAuthRe.ReplaceAllString(cleaned, "${1}:[REDACTED]@")

	// 3. Redact Bearer tokens
	cleaned = bearerRe.ReplaceAllString(cleaned, "Bearer [REDACTED]")

	// 4. Redact headers
	cleaned = headerSecretRe.ReplaceAllString(cleaned, "${1}: [REDACTED]")

	// 5. Redact query parameter values
	cleaned = querySecretRe.ReplaceAllString(cleaned, "${1}=[REDACTED]")

	// 6. Clean whitespace
	cleaned = strings.TrimSpace(cleaned)

	// 7. Bound length to maxMessageLength
	if len(cleaned) > maxMessageLength {
		cleaned = cleaned[:maxMessageLength-15] + "... [truncated]"
	}

	return cleaned
}
