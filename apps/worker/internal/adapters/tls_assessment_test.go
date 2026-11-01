package adapters

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

func TestTLSAssessmentAdapterCapturesValidCertificateAndProtocol(t *testing.T) {
	withLabMode(t)
	server, cert := startTLSAssessmentServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), tls.VersionTLS12, tls.VersionTLS13, nil)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	result := executeTLSAssessment(t, roots, tlsAssessmentPolicy(t), tlsAssessmentTask(t, server.URL))
	if result.Status != StatusCompleted || len(result.Findings) != 0 {
		t.Fatalf("valid certificate produced unexpected result: status=%s findings=%s", result.Status, result.Findings)
	}
	observation := decodeTLSObservation(t, result)
	if observation.Outcome != "TLS_ESTABLISHED" || !observation.ChainTrusted || !observation.HostnameMatch || len(observation.Certificates) != 1 {
		t.Fatalf("certificate/protocol observation incomplete: %+v", observation)
	}
	if observation.ProtocolVersion == "" || observation.CipherSuite == "" || result.ScannerMetadata["tls_assessment.rule_set_version"] == nil {
		t.Fatalf("protocol, cipher, or rule version missing: %+v", observation)
	}
}

func TestTLSAssessmentAdapterReportsExpiredCertificateFinding(t *testing.T) {
	withLabMode(t)
	server, cert := startTLSAssessmentServer(t, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), tls.VersionTLS12, tls.VersionTLS13, nil)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	result := executeTLSAssessment(t, roots, tlsAssessmentPolicy(t), tlsAssessmentTask(t, server.URL))
	if result.Status != StatusCompleted || len(result.Findings) != 1 {
		t.Fatalf("expired certificate findings=%d status=%s", len(result.Findings), result.Status)
	}
	var finding map[string]any
	if err := json.Unmarshal(result.Findings[0], &finding); err != nil {
		t.Fatal(err)
	}
	if finding["title"] != "TLS certificate is expired" || finding["severity"] != "HIGH" {
		t.Fatalf("unexpected expired certificate finding: %+v", finding)
	}
	if observation := decodeTLSObservation(t, result); observation.TrustEvaluation != "INVALID_VALIDITY_PERIOD" {
		t.Fatalf("expired chain was not classified separately from trust: %+v", observation)
	}
}

func TestTLSAssessmentAdapterReportsDeprecatedTLSProtocol(t *testing.T) {
	withLabMode(t)
	cipher := []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA}
	server, cert := startTLSAssessmentServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), tls.VersionTLS10, tls.VersionTLS10, cipher)
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(cert.Leaf)
	result := executeTLSAssessment(t, roots, tlsAssessmentPolicy(t), tlsAssessmentTask(t, server.URL))
	if result.Status != StatusCompleted {
		t.Fatalf("legacy protocol handshake status=%s diagnostics=%+v", result.Status, result.Diagnostics)
	}
	if len(result.Findings) < 2 {
		t.Fatalf("expected legacy protocol and CBC findings, got %d", len(result.Findings))
	}
	joined := string(result.Findings[0]) + string(result.Findings[1])
	if !strings.Contains(joined, "kelvin.tls.protocol.legacy") || !strings.Contains(joined, "kelvin.tls.cipher.weak") {
		t.Fatalf("legacy TLS protocol/cipher findings missing: %s", joined)
	}
}

func TestTLSAssessmentAdapterReportsHostnameAndUntrustedChain(t *testing.T) {
	withLabMode(t)
	server, _ := startTLSAssessmentServer(t, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), tls.VersionTLS12, tls.VersionTLS13, nil)
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := scope.NewPolicy([]string{"wrong.localhost"}, nil, preflightResolver{ip: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	target := "https://" + net.JoinHostPort("wrong.localhost", serverURL.Port()) + "/"
	result := executeTLSAssessment(t, nil, policy, tlsAssessmentTask(t, target))
	if result.Status != StatusCompleted || len(result.Findings) == 0 {
		t.Fatalf("untrusted certificate findings=%d status=%s", len(result.Findings), result.Status)
	}
	joined := string(result.Findings[0])
	for _, finding := range result.Findings[1:] {
		joined += string(finding)
	}
	if !strings.Contains(joined, "kelvin.tls.certificate.untrusted") || !strings.Contains(joined, "kelvin.tls.certificate.hostname_mismatch") {
		t.Fatalf("certificate validation findings missing: %s", joined)
	}
}

func TestTLSAssessmentAdapterRecordsConnectionFailureAsDiagnostic(t *testing.T) {
	withLabMode(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	task := tlsAssessmentTask(t, "https://127.0.0.1:"+strconv.Itoa(port)+"/")
	result := executeTLSAssessment(t, nil, tlsAssessmentPolicy(t), task)
	if result.Status != StatusCompletedWithWarnings || len(result.Findings) != 0 || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "TLS_CONNECTION_FAILED" {
		t.Fatalf("connection failure was not separated from findings: %+v", result)
	}
}

func TestTLSAssessmentRejectsHTTPAndMissingScopeProvider(t *testing.T) {
	if err := NewTLSAssessmentAdapter(nil, nil).Initialize(context.Background(), zap.NewNop()); err == nil {
		t.Fatal("adapter initialized without a scope provider")
	}
	withLabMode(t)
	adapter := NewTLSAssessmentAdapter(func(context.Context, Task) (scope.Policy, error) { return tlsAssessmentPolicy(t), nil }, nil)
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	task := tlsAssessmentTask(t, "http://127.0.0.1/")
	if _, err := adapter.Execute(context.Background(), task); err == nil {
		t.Fatal("TLS assessor accepted an HTTP target")
	}
}

func executeTLSAssessment(t *testing.T, roots *x509.CertPool, policy scope.Policy, task Task) Result {
	t.Helper()
	adapter := NewTLSAssessmentAdapter(func(context.Context, Task) (scope.Policy, error) { return policy, nil }, roots)
	if err := adapter.Initialize(context.Background(), zap.NewNop()); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ValidateConfig(task.Payload); err != nil {
		t.Fatalf("TLS config rejected: %v", err)
	}
	result, err := adapter.Execute(context.Background(), task)
	if err != nil {
		t.Fatalf("TLS Execute failed: %v", err)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("invalid TLS output envelope: %v", err)
	}
	return result
}

func tlsAssessmentPolicy(t *testing.T) scope.Policy {
	t.Helper()
	policy, err := scope.NewPolicy(nil, []string{"127.0.0.0/8"}, preflightResolver{ip: netip.MustParseAddr("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func tlsAssessmentTask(t *testing.T, target string) Task {
	t.Helper()
	config, err := DefaultScannerConfig(ScannerTLSAssessor)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return Task{
		JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID: "33333333-3333-3333-3333-333333333333", CorrelationID: "tls-assessment-correlation",
		Scanner: ScannerTLSAssessor, Target: target, ProfileID: "kelvin.profile.standard.v1",
		HardDeadline: 5 * time.Second, Payload: raw,
	}
}

func startTLSAssessmentServer(t *testing.T, notBefore, notAfter time.Time, minVersion, maxVersion uint16, cipherSuites []uint16) (*httptest.Server, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: notBefore, NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: minVersion, MaxVersion: maxVersion, CipherSuites: cipherSuites}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, certificate
}

func decodeTLSObservation(t *testing.T, result Result) tlsObservation {
	t.Helper()
	var observation tlsObservation
	if err := json.Unmarshal(result.ScannerMetadata["tls_assessment.observation"], &observation); err != nil {
		t.Fatalf("decode TLS observation: %v", err)
	}
	return observation
}
