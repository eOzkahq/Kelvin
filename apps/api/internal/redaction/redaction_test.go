package redaction

import (
	"net/http"
	"testing"

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

func TestRedactorRedactHeaders(t *testing.T) {
	red := NewDefaultRedactor()
	h := http.Header{
		"Authorization":   {"Bearer secret-token"},
		"Set-Cookie":      {"session_id=abc123; Path=/; HttpOnly"},
		"Cookie":          {"session_id=def456; other=xyz"},
		"X-Custom-Header": {"keep-this-value"},
		"Content-Type":    {"application/json"},
	}
	red.RedactHeaders(h)
	require.Equal(t, "[REDACTED]", h.Get("Authorization"))
	require.Contains(t, h.Get("Set-Cookie"), "session_id=[REDACTED]")
	require.Contains(t, h.Get("Cookie"), "session_id=[REDACTED]")
	require.Equal(t, "keep-this-value", h.Get("X-Custom-Header"))
	require.Equal(t, "application/json", h.Get("Content-Type"))
}

func TestCustomRedactor(t *testing.T) {
	red, err := NewCustomRedactor([]string{
		`(?i)(my_custom_secret\s*=\s*)[^\s,;}]+`,
	})
	require.NoError(t, err)
	out := red.RedactString(`my_custom_secret = hidden-value`)
	require.Contains(t, out, "[REDACTED]")
	require.NotContains(t, out, "hidden-value")
}

func TestCustomRedactorInvalidPattern(t *testing.T) {
	_, err := NewCustomRedactor([]string{`[invalid-regex`})
	require.Error(t, err)
}

func TestRedactFinding(t *testing.T) {
	input := []byte(`{
		"schema_version": "1.0",
		"title": "Test finding",
		"evidence": [
			{"type": "HTTP_EXCHANGE", "content_redacted": "Authorization: Bearer secret-jwt-token-here"}
		]
	}`)
	out := RedactFinding(input)
	require.Contains(t, string(out), "[REDACTED]")
	require.NotContains(t, string(out), "secret-jwt-token-here")
}
