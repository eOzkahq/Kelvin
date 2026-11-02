package evidence_test

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/kelvin/kelvin/apps/api/internal/evidence"
)

func TestSanitizerEngine_SecretRedaction(t *testing.T) {
	engine := evidence.NewSanitizerEngine()

	samplePayload := `POST /login HTTP/1.1
Host: secure.kelvin.internal
User-Agent: Mozilla/5.0
Authorization: Bearer secret_jwt_payload_12345
Cookie: session_id=abcde12345; auth=ok
Content-Type: application/x-www-form-urlencoded

username=admin&password=SuperSecretPassword123!&api_key=sk_live_9999999
`

	redacted, rules := engine.RedactText(samplePayload)

	assert.Contains(t, redacted, "Host: secure.kelvin.internal")
	assert.Contains(t, redacted, "User-Agent: Mozilla/5.0")
	assert.Contains(t, redacted, "username=admin")

	assert.NotContains(t, redacted, "secret_jwt_payload_12345")
	assert.Contains(t, redacted, evidence.MaskAuthToken)

	assert.NotContains(t, redacted, "abcde12345")
	assert.Contains(t, redacted, evidence.MaskCookie)

	assert.NotContains(t, redacted, "SuperSecretPassword123!")
	assert.Contains(t, redacted, evidence.MaskPassword)

	assert.NotContains(t, redacted, "sk_live_9999999")
	assert.Contains(t, redacted, evidence.MaskAPIKey)

	assert.ElementsMatch(t, []string{
		"AUTHORIZATION_BEARER",
		"COOKIE_HEADER",
		"PASSWORD_FIELD",
		"API_KEY_FIELD",
	}, rules)
}

func TestSanitizerEngine_JWTPrivateKeyAndAWSSecrets(t *testing.T) {
	engine := evidence.NewSanitizerEngine()

	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	pemKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3...\n-----END RSA PRIVATE KEY-----"
	awsSecret := "aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	text := "Debug Info:\nToken: " + jwtToken + "\nKey:\n" + pemKey + "\nAWS:\n" + awsSecret

	redacted, rules := engine.RedactText(text)

	assert.NotContains(t, redacted, jwtToken)
	assert.Contains(t, redacted, evidence.MaskJWT)

	assert.NotContains(t, redacted, "MIIEowIBAAKCAQEA0Y3")
	assert.Contains(t, redacted, evidence.MaskPrivateKey)

	assert.NotContains(t, redacted, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	assert.Contains(t, redacted, evidence.MaskAPIKey)

	assert.Contains(t, rules, "JWT_TOKEN")
	assert.Contains(t, rules, "PEM_PRIVATE_KEY")
	assert.Contains(t, rules, "AWS_SECRET_KEY")
}

func TestSanitizerEngine_PreservesHarmlessTraffic(t *testing.T) {
	engine := evidence.NewSanitizerEngine()

	harmlessHTTP := `GET /api/v1/metrics?limit=100&offset=0 HTTP/1.1
Host: api.example.com
Accept: application/json
Accept-Encoding: gzip, deflate
Cache-Control: no-cache
Connection: keep-alive

{"status":"healthy","uptime":3600}`

	redacted, rules := engine.RedactText(harmlessHTTP)

	assert.Equal(t, harmlessHTTP, redacted)
	assert.Empty(t, rules)
}

func TestSanitizerService_PresentationEnvelope(t *testing.T) {
	svc := evidence.NewSanitizerService()

	item := &evidence.EvidenceItem{
		ID:               uuid.New().String(),
		TenantID:         uuid.New().String(),
		ProjectID:        uuid.New().String(),
		AssessmentID:     uuid.New().String(),
		JobID:            uuid.New().String(),
		EvidenceType:     evidence.TypeHTTPObservation,
		Provenance:       evidence.ProvenanceCuratedFinding,
		ContentType:      "text/plain",
		InlineContent:    "GET /test HTTP/1.1\r\nAuthorization: Bearer secret-token-xyz\r\n\r\n200 OK",
		ChecksumSHA256:   strings.Repeat("a", 64),
		SizeBytes:        60,
		RedactionStatus:  evidence.RedactionUnredactedInternal,
		SensitivityLevel: evidence.SensitivityInternal,
		Status:           evidence.StatusActive,
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	// 1. Unprivileged user receives sanitized envelope
	env, err := svc.PreparePresentationEnvelope(item, false, nil)
	require.NoError(t, err)
	assert.False(t, env.IsUnredactedRaw)
	assert.Contains(t, env.SanitizedContent, evidence.MaskAuthToken)
	assert.NotContains(t, env.SanitizedContent, "secret-token-xyz")
	assert.Equal(t, evidence.RedactionRuleVersion, env.RuleVersion)
	assert.Equal(t, evidence.RedactionSanitizedPresentation, env.RedactionStatus)

	// 2. Privileged internal access returns original content
	privEnv, err := svc.PreparePresentationEnvelope(item, true, nil)
	require.NoError(t, err)
	require.NotNil(t, privEnv)
	assert.True(t, privEnv.IsUnredactedRaw)
	assert.Contains(t, privEnv.SanitizedContent, "secret-token-xyz")

	// 3. Manual analyst redaction overlay
	manualReq := &evidence.ManualRedactionRequest{
		TargetPatterns: []string{`200 OK`},
		Reason:         "Mask status code in proprietary test",
		AnalystID:      "analyst-123",
	}
	manualEnv, err := svc.PreparePresentationEnvelope(item, false, manualReq)
	require.NoError(t, err)
	assert.Contains(t, manualEnv.SanitizedContent, evidence.MaskManualSecret)
	assert.NotContains(t, manualEnv.SanitizedContent, "200 OK")
	assert.Contains(t, manualEnv.RedactedFields, "MANUAL_ANALYST_OVERLAY")
}
