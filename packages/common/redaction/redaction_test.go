package redaction

import (
	"strings"
	"testing"

	commonnorm "github.com/kelvin/kelvin/packages/common/normalization"
	"github.com/stretchr/testify/require"
)

func TestDefaultRedactorRedactsBearerToken(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNtPgIhzFAO3CZ5t4yG9t2xF6s5h7j8k9l0m1n2`)
	require.Contains(t, out, "[REDACTED]")
	require.NotContains(t, out, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
}

func TestDefaultRedactorRedactsBasicAuth(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`Authorization: Basic dXNlcjpwYXNzd29yZA==`)
	require.Contains(t, out, "[REDACTED]")
	require.NotContains(t, out, "dXNlcjpwYXNzd29yZA==")
}

func TestDefaultRedactorRedactsSetCookie(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`Set-Cookie: session_id=abc123def456; Path=/; HttpOnly`)
	require.Contains(t, out, "session_id=[REDACTED]")
	require.Contains(t, out, "Path=/")
	require.Contains(t, out, "HttpOnly")
	require.NotContains(t, out, "abc123def456")
}

func TestDefaultRedactorRedactsCookie(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`Cookie: session_id=abc123def456; other=xyz`)
	require.Contains(t, out, "session_id=[REDACTED]")
	require.Contains(t, out, "other=xyz")
	require.NotContains(t, out, "abc123def456")
}

func TestDefaultRedactorRedactsPasswordField(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`password=supersecret123&username=admin`)
	require.Contains(t, out, `password=[REDACTED]`)
	require.Contains(t, out, `username=admin`)
	require.NotContains(t, out, "supersecret123")
}

func TestDefaultRedactorRedactsSecretField(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`api_key=ak-1234567890abcdef&name=test`)
	require.Contains(t, out, `api_key=[REDACTED]`)
	require.NotContains(t, out, "ak-1234567890abcdef")
}

func TestDefaultRedactorRedactsTokenField(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`token=my-secret-token-value&other=keep`)
	require.Contains(t, out, `token=[REDACTED]`)
	require.Contains(t, out, `other=keep`)
	require.NotContains(t, out, "my-secret-token-value")
}

func TestDefaultRedactorRedactsAuthorizationHeader(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`authorization: some-random-token-value`)
	require.Contains(t, out, "authorization: [REDACTED]")
	require.NotContains(t, out, "some-random-token-value")
}

func TestDefaultRedactorRedactsJWT(t *testing.T) {
	red := NewDefaultRedactor()
	jwt := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNtPgIhzFAO3CZ5t4yG9t2xF6s5h7j8k9l0m1n2`
	out := red.RedactString(`token: ` + jwt)
	require.Contains(t, out, "[REDACTED]")
	require.NotContains(t, out, jwt)
}

func TestDefaultRedactorRedactsAWSSecretKey(t *testing.T) {
	red := NewDefaultRedactor()
	out := red.RedactString(`aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`)
	require.Contains(t, out, "[REDACTED]")
	require.NotContains(t, out, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
}

func TestDefaultRedactorRedactsPEMPrivateKey(t *testing.T) {
	red := NewDefaultRedactor()
	pem := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`
	out := red.RedactString(pem)
	require.Contains(t, out, "[REDACTED]")
	require.NotContains(t, out, "MIIEpAIBAAKCAQEA")
}

func TestDefaultRedactorPreservesNonSensitiveData(t *testing.T) {
	red := NewDefaultRedactor()
	in := `{"hostname": "example.com", "status_code": 200, "title": "Test Page"}`
	out := red.RedactString(in)
	require.Equal(t, in, out)
}

func TestRedactHeaders(t *testing.T) {
	red := NewDefaultRedactor()
	h := map[string][]string{
		"Authorization": {"Bearer secret-token-xyz"},
		"Cookie":        {"session=sess-12345; theme=dark"},
		"X-Custom":      {"normal-header-value"},
	}
	red.RedactHeaders(h)
	require.Equal(t, []string{"[REDACTED]"}, h["Authorization"])
	require.Equal(t, []string{"session=[REDACTED]; theme=dark"}, h["Cookie"])
	require.Equal(t, []string{"normal-header-value"}, h["X-Custom"])
}

func TestRedactEvidenceContentAndEnforceBounds(t *testing.T) {
	red := NewDefaultRedactor()

	// 1. Scrub credentials and collect category metadata
	rawHTTP := "GET /admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer my-top-secret-token\r\nCookie: session_id=sess-secret\r\n\r\n"
	sanitized, categories := red.RedactEvidenceContent(rawHTTP)
	require.NotContains(t, sanitized, "my-top-secret-token")
	require.NotContains(t, sanitized, "sess-secret")
	require.Contains(t, sanitized, "Authorization: [REDACTED]")
	require.Contains(t, sanitized, "session_id=[REDACTED]")
	require.Contains(t, categories, "authorization_bearer")
	require.Contains(t, categories, "cookie")

	// 2. Oversized evidence truncated at 64KiB ceiling
	oversized := strings.Repeat("A", 70000)
	bounded, bCategories := red.RedactEvidenceContent(oversized)
	require.LessOrEqual(t, len(bounded), MaxEvidenceBytesPerFinding)
	require.Contains(t, bounded, "[TRUNCATED: EXCEEDED 64KiB EVIDENCE CEILING]")
	require.Contains(t, bCategories, "truncated_oversized_evidence")
}

func TestRedactFindingModel(t *testing.T) {
	red := NewDefaultRedactor()

	finding := &commonnorm.CanonicalFinding{
		Title: "Sensitive Data Exposure",
		ReproductionSteps: []string{
			"curl -H 'Authorization: Bearer token-123' https://example.com/api",
		},
		Evidence: []commonnorm.Evidence{
			{
				Type:            "HTTP_EXCHANGE",
				ContentRedacted: "HTTP/1.1 200 OK\r\nSet-Cookie: token=token-secret-abc;\r\n\r\npassword=admin-pass",
			},
		},
	}

	red.RedactFinding(finding)

	require.NotContains(t, finding.ReproductionSteps[0], "token-123")
	require.Contains(t, finding.ReproductionSteps[0], "[REDACTED]")

	ev := finding.Evidence[0]
	require.NotContains(t, ev.ContentRedacted, "token-secret-abc")
	require.NotContains(t, ev.ContentRedacted, "admin-pass")
	require.Contains(t, ev.RedactedFields, "password")
	require.Contains(t, ev.RedactedFields, "set_cookie")
	require.NotEmpty(t, ev.ChecksumSHA256)
	require.Equal(t, int64(len(ev.ContentRedacted)), ev.SizeBytes)
}
