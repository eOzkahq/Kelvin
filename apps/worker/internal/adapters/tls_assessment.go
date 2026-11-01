package adapters

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

const TLSRuleSetVersion = "kelvin.tls.rules.v1"

var tlsAssessmentCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

// TLSAssessmentAdapter performs a bounded, scoped TLS handshake matrix and
// evaluates accepted protocol versions, negotiated ciphers, and certificates.
// It does not send application data or run exploit-oriented probes.
type TLSAssessmentAdapter struct {
	*ReferenceAdapter
	policyForTask ScopePolicyProvider
	roots         *x509.CertPool
	rateMu        sync.Mutex
	nextRequest   time.Time
}

// NewTLSAssessmentAdapter creates the built-in tls_assessor. roots is an
// optional trusted root set; nil uses the host system roots. Both the scope
// provider and root set are trusted worker dependencies, never user config.
func NewTLSAssessmentAdapter(policyForTask ScopePolicyProvider, roots *x509.CertPool) *TLSAssessmentAdapter {
	adapter := &TLSAssessmentAdapter{
		ReferenceAdapter: &ReferenceAdapter{
			AdapterName: ScannerTLSAssessor,
			Caps: Capabilities{
				CheckCategories:      []string{"tls_protocol", "tls_cipher", "tls_certificate"},
				SupportedTargetTypes: []string{"url"}, SupportedProtocols: []string{"https"},
				PassiveOnly: true, RequiresNetwork: true, SupportsCancel: true,
				MaxConcurrency: 1, MaxRequestRate: 2, MaxRequests: 4,
			},
		},
		policyForTask: policyForTask,
		roots:         roots,
	}
	adapter.Run = adapter.run
	return adapter
}

func (a *TLSAssessmentAdapter) Initialize(ctx context.Context, logger *zap.Logger) error {
	if a.policyForTask == nil {
		return fmt.Errorf("adapters: TLS assessment requires a trusted scope policy provider")
	}
	return a.ReferenceAdapter.Initialize(ctx, logger)
}

func (a *TLSAssessmentAdapter) ValidateConfig(raw json.RawMessage) error {
	config, err := tlsAssessmentConfig(Task{Scanner: ScannerTLSAssessor, Payload: raw})
	if err != nil {
		return err
	}
	if config.RequestsPerSecond > a.Capabilities().MaxRequestRate || config.MaxConcurrency > a.Capabilities().MaxConcurrency {
		return fmt.Errorf("adapters: TLS assessment config exceeds adapter request or concurrency limits")
	}
	return nil
}

func (a *TLSAssessmentAdapter) run(ctx context.Context, task Task) (Result, error) {
	config, err := tlsAssessmentConfig(task)
	if err != nil {
		return Result{}, err
	}
	if err := a.ValidateConfig(task.Payload); err != nil {
		return Result{}, err
	}
	started := time.Now().UTC()
	deadline := minTLSAssessmentDuration(time.Duration(config.MaxDurationSeconds)*time.Second, task.HardDeadline)
	operationCtx, operationCancel := context.WithTimeout(ctx, deadline)
	defer operationCancel()
	policy, err := a.policyForTask(operationCtx, task)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: load authorized target scope: %w", err)
	}
	target, _, err := policy.Validate(operationCtx, task.Target)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: TLS target rejected by scope policy: %w", err)
	}
	targetURL, err := url.Parse(target.Canonical)
	if err != nil || targetURL == nil || targetURL.Scheme != "https" || target.Host == "" {
		return Result{}, fmt.Errorf("adapters: TLS assessment requires an approved HTTPS URL")
	}
	requestTimeout := minTLSAssessmentDuration(time.Duration(config.RequestTimeoutSeconds)*time.Second, deadline)
	connectStarted := time.Now()
	transport := policy.NewTransport()
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}
	attempts := make([]tlsProtocolAttempt, 0, len(versions))
	states := make([]tls.ConnectionState, 0, len(versions))
	diagnostics := []ExecutionDiagnostic{}
	var lastHandshakeErr error
	for _, version := range versions {
		if err := a.waitForRequestSlot(operationCtx, config.RequestsPerSecond); err != nil {
			if len(states) == 0 {
				return a.finishFailure(task, target.Canonical, started, connectStarted, operationCtx, err, "handshake")
			}
			diagnostics = append(diagnostics, ExecutionDiagnostic{Level: "warning", Code: "TLS_PROBE_BUDGET_EXHAUSTED", Message: "TLS protocol evaluation stopped at the task deadline"})
			break
		}
		handshakeCtx, handshakeCancel := context.WithTimeout(operationCtx, requestTimeout)
		conn, dialErr := transport.DialContext(handshakeCtx, "tcp", net.JoinHostPort(target.Host, target.Port))
		if dialErr != nil {
			handshakeCancel()
			if len(states) == 0 {
				return a.finishFailure(task, target.Canonical, started, connectStarted, operationCtx, dialErr, "connection")
			}
			diagnostics = append(diagnostics, ExecutionDiagnostic{Level: "warning", Code: "TLS_CONNECTION_FAILED", Message: "A TLS protocol check could not open a connection"})
			break
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: target.Host, InsecureSkipVerify: true, // Verification is performed explicitly below to retain invalid-certificate details.
			MinVersion: version, MaxVersion: version,
			CipherSuites: append([]uint16(nil), tlsAssessmentCipherSuites...),
		})
		handshakeErr := tlsConn.HandshakeContext(handshakeCtx)
		handshakeCancel()
		_ = conn.Close()
		attempt := tlsProtocolAttempt{Version: tls.VersionName(version)}
		if handshakeErr != nil {
			attempt.Error = classifyTLSAttemptError(handshakeErr, operationCtx)
			lastHandshakeErr = handshakeErr
			if attempt.Error == "handshake_failed" {
				diagnostics = append(diagnostics, ExecutionDiagnostic{Level: "warning", Code: "TLS_HANDSHAKE_FAILED", Message: "A TLS protocol check failed before configuration could be evaluated"})
			}
			attempts = append(attempts, attempt)
			continue
		}
		state := tlsConn.ConnectionState()
		attempt.Supported = true
		attempt.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
		attempts = append(attempts, attempt)
		states = append(states, state)
	}
	if len(states) == 0 {
		if lastHandshakeErr == nil {
			lastHandshakeErr = errors.New("TLS handshake did not negotiate a supported protocol")
		}
		return a.finishFailure(task, target.Canonical, started, connectStarted, operationCtx, lastHandshakeErr, "handshake")
	}
	completed := time.Now().UTC()
	observation, findings, tlsDiagnostics, err := a.evaluateTLS(target.Host, target.Canonical, states, attempts, completed)
	if err != nil {
		return Result{}, err
	}
	diagnostics = append(diagnostics, tlsDiagnostics...)
	observationJSON, err := json.Marshal(observation)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: encode TLS observation: %w", err)
	}
	ruleSetJSON, _ := json.Marshal(TLSRuleSetVersion)
	resultStatus := StatusCompleted
	if len(diagnostics) > 0 {
		resultStatus = StatusCompletedWithWarnings
	}
	return Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID: task.AssessmentID, ScannerID: ScannerTLSAssessor,
			ScannerVersion: a.Version(), AdapterVersion: a.Version(), RunID: uuid.NewString(),
			StartedAt: started, CompletedAt: completed, CorrelationID: task.CorrelationID,
		},
		Status: resultStatus, ExitCode: intPointer(0), DurationMS: time.Since(started).Milliseconds(),
		Findings: findings, Diagnostics: diagnostics,
		ScannerMetadata: map[string]json.RawMessage{
			"tls_assessment.observation":      observationJSON,
			"tls_assessment.rule_set_version": ruleSetJSON,
		},
		RawArtifacts: RawArtifactReferences{},
	}, nil
}

func (a *TLSAssessmentAdapter) evaluateTLS(host, canonical string, states []tls.ConnectionState, attempts []tlsProtocolAttempt, observedAt time.Time) (tlsObservation, []json.RawMessage, []ExecutionDiagnostic, error) {
	preferred := states[len(states)-1]
	observation := tlsObservation{
		Outcome: "TLS_ESTABLISHED", Target: canonical,
		ProtocolVersion: tls.VersionName(preferred.Version), CipherSuite: tls.CipherSuiteName(preferred.CipherSuite),
		ALPN: preferred.NegotiatedProtocol, RuleSetVersion: TLSRuleSetVersion,
		ProtocolAttempts: attempts, SupportedProtocols: make([]string, 0, len(states)), CipherSuites: make([]string, 0, len(states)),
	}
	findings := make([]json.RawMessage, 0)
	diagnostics := []ExecutionDiagnostic{}
	seenFindings := make(map[string]bool)
	var findingErr error
	add := func(id, title, severity, description, remediation string) {
		if findingErr != nil || seenFindings[id] {
			return
		}
		finding, err := makeTLSFinding(host, canonical, id, title, severity, description, remediation, observedAt)
		if err != nil {
			findingErr = err
			return
		}
		seenFindings[id] = true
		findings = append(findings, finding)
	}
	for _, state := range states {
		versionName := tls.VersionName(state.Version)
		cipherName := tls.CipherSuiteName(state.CipherSuite)
		observation.SupportedProtocols = append(observation.SupportedProtocols, versionName)
		observation.CipherSuites = append(observation.CipherSuites, cipherName)
		if state.Version < tls.VersionTLS12 {
			add("kelvin.tls.protocol.legacy", "Deprecated TLS protocol is supported", "HIGH",
				"The server accepted "+versionName+", which is below the approved TLS 1.2 minimum.",
				"Disable TLS 1.0 and TLS 1.1 and require TLS 1.2 or newer.")
		}
		if isWeakTLSCipher(cipherName) {
			severity := "MEDIUM"
			if strings.Contains(cipherName, "RC4") || strings.Contains(cipherName, "3DES") || strings.Contains(cipherName, "_NULL_") {
				severity = "HIGH"
			}
			add("kelvin.tls.cipher.weak", "Weak TLS cipher is supported", severity,
				"The server negotiated the deprecated cipher suite "+cipherName+".",
				"Disable deprecated CBC, RC4, 3DES, and NULL cipher suites; prefer AEAD suites.")
		}
	}
	observation.Certificates = describeCertificates(preferred.PeerCertificates)
	if len(preferred.PeerCertificates) == 0 {
		observation.ChainTrusted = false
		diagnostics = append(diagnostics, ExecutionDiagnostic{Level: "warning", Code: "TLS_CERTIFICATE_MISSING", Message: "No peer certificate was presented by the TLS server"})
		return observation, findings, diagnostics, nil
	}
	leaf := preferred.PeerCertificates[0]
	now := observedAt
	for index, cert := range preferred.PeerCertificates {
		if now.After(cert.NotAfter) {
			add("kelvin.tls.certificate.expired", "TLS certificate is expired", "HIGH",
				fmt.Sprintf("Certificate %d in the presented chain expired at %s.", index, cert.NotAfter.UTC().Format(time.RFC3339)),
				"Renew the certificate and deploy a currently valid chain.")
		}
		if now.Before(cert.NotBefore) {
			add("kelvin.tls.certificate.not_yet_valid", "TLS certificate is not yet valid", "MEDIUM",
				fmt.Sprintf("Certificate %d in the presented chain is not valid before %s.", index, cert.NotBefore.UTC().Format(time.RFC3339)),
				"Check certificate issuance and system clock; deploy a certificate valid for the current period.")
		}
	}
	hostnameErr := leaf.VerifyHostname(host)
	observation.HostnameMatch = hostnameErr == nil
	if hostnameErr != nil {
		add("kelvin.tls.certificate.hostname_mismatch", "TLS certificate hostname mismatch", "HIGH",
			"The presented leaf certificate does not identify the approved target hostname.",
			"Issue and deploy a certificate whose subject alternative name matches the target hostname.")
	}
	roots := a.roots
	if roots == nil {
		roots, _ = x509.SystemCertPool()
	}
	if roots == nil {
		observation.ChainTrusted = false
		observation.TrustEvaluation = "ROOT_STORE_UNAVAILABLE"
		diagnostics = append(diagnostics, ExecutionDiagnostic{Level: "warning", Code: "TLS_TRUST_STORE_UNAVAILABLE", Message: "TLS certificate trust could not be evaluated because no root store is available"})
		return observation, findings, diagnostics, findingErr
	}
	intermediates := x509.NewCertPool()
	for _, cert := range preferred.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now})
	observation.ChainTrusted = verifyErr == nil
	if verifyErr == nil {
		observation.TrustEvaluation = "TRUSTED"
	} else if isCertificateValidityError(verifyErr) {
		observation.TrustEvaluation = "INVALID_VALIDITY_PERIOD"
	} else {
		observation.TrustEvaluation = "UNTRUSTED_CHAIN"
		add("kelvin.tls.certificate.untrusted", "TLS certificate chain is not trusted", "MEDIUM",
			"The presented certificate chain could not be verified against the configured trust roots.",
			"Deploy the complete chain from a trusted certificate authority and remove expired or untrusted intermediates.")
	}
	return observation, findings, diagnostics, findingErr
}

func (a *TLSAssessmentAdapter) finishFailure(task Task, target string, started, attemptStarted time.Time, ctx context.Context, cause error, phase string) (Result, error) {
	completed := time.Now().UTC()
	status := StatusCompletedWithWarnings
	code := "TLS_HANDSHAKE_FAILED"
	message := "TLS connection could not be established"
	errorCategory := "tls_handshake_failed"
	if phase == "connection" {
		code, message, errorCategory = "TLS_CONNECTION_FAILED", "TCP connection to the approved TLS target failed", "connection_failed"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		status, code, message, errorCategory = StatusTimedOut, "DEADLINE_EXCEEDED", "TLS assessment exceeded its configured timeout", "timeout"
	} else if errors.Is(ctx.Err(), context.Canceled) {
		status, code, message, errorCategory = StatusCancelled, "CANCELLED", "TLS assessment was cancelled", "cancelled"
	}
	if strings.Contains(strings.ToLower(cause.Error()), "protocol version") {
		code, errorCategory = "TLS_PROTOCOL_NEGOTIATION_FAILED", "protocol_negotiation_failed"
	}
	observation, _ := json.Marshal(tlsObservation{
		Outcome: "TLS_FAILED", Target: target, RuleSetVersion: TLSRuleSetVersion,
		Error: errorCategory, DurationMS: time.Since(attemptStarted).Milliseconds(),
	})
	diagnosticLevel := "warning"
	if status == StatusTimedOut || status == StatusCancelled {
		diagnosticLevel = "error"
	}
	runID := uuid.NewString()
	return Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID: task.AssessmentID, ScannerID: ScannerTLSAssessor,
			ScannerVersion: a.Version(), AdapterVersion: a.Version(), RunID: runID,
			StartedAt: started, CompletedAt: completed, CorrelationID: task.CorrelationID,
		},
		Status: status, ExitCode: intPointer(0), DurationMS: time.Since(started).Milliseconds(),
		Findings: []json.RawMessage{}, Diagnostics: []ExecutionDiagnostic{{Level: diagnosticLevel, Code: code, Message: message}},
		ScannerMetadata: map[string]json.RawMessage{
			"tls_assessment.observation":      observation,
			"tls_assessment.rule_set_version": json.RawMessage(`"` + TLSRuleSetVersion + `"`),
		},
		RawArtifacts: RawArtifactReferences{},
	}, nil
}

func (a *TLSAssessmentAdapter) waitForRequestSlot(ctx context.Context, requestsPerSecond int) error {
	interval := time.Second / time.Duration(requestsPerSecond)
	a.rateMu.Lock()
	now := time.Now()
	wait := a.nextRequest.Sub(now)
	if wait <= 0 {
		a.nextRequest = now.Add(interval)
		a.rateMu.Unlock()
		return nil
	}
	a.nextRequest = a.nextRequest.Add(interval)
	a.rateMu.Unlock()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

type tlsObservation struct {
	Outcome            string               `json:"outcome"`
	Target             string               `json:"target"`
	ProtocolVersion    string               `json:"protocol_version,omitempty"`
	SupportedProtocols []string             `json:"supported_protocols"`
	ProtocolAttempts   []tlsProtocolAttempt `json:"protocol_attempts"`
	CipherSuite        string               `json:"cipher_suite,omitempty"`
	CipherSuites       []string             `json:"cipher_suites"`
	ALPN               string               `json:"alpn,omitempty"`
	ChainTrusted       bool                 `json:"chain_trusted"`
	TrustEvaluation    string               `json:"trust_evaluation,omitempty"`
	HostnameMatch      bool                 `json:"hostname_match"`
	Certificates       []tlsCertObservation `json:"certificates"`
	RuleSetVersion     string               `json:"rule_set_version"`
	Error              string               `json:"error,omitempty"`
	DurationMS         int64                `json:"duration_ms,omitempty"`
}

type tlsProtocolAttempt struct {
	Version     string `json:"version"`
	Supported   bool   `json:"supported"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	Error       string `json:"error,omitempty"`
}

type tlsCertObservation struct {
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	DNSNames          []string  `json:"dns_names"`
	IPAddresses       []string  `json:"ip_addresses"`
}

func describeCertificates(certs []*x509.Certificate) []tlsCertObservation {
	if len(certs) > 10 {
		certs = certs[:10]
	}
	descriptions := make([]tlsCertObservation, 0, len(certs))
	for _, cert := range certs {
		fingerprint := sha256.Sum256(cert.Raw)
		dnsNames := cert.DNSNames
		if len(dnsNames) > 20 {
			dnsNames = dnsNames[:20]
		}
		ips := cert.IPAddresses
		if len(ips) > 20 {
			ips = ips[:20]
		}
		ipStrings := make([]string, 0, len(ips))
		for _, ip := range ips {
			ipStrings = append(ipStrings, ip.String())
		}
		descriptions = append(descriptions, tlsCertObservation{
			FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
			Subject:           boundedString(cert.Subject.String(), 256),
			Issuer:            boundedString(cert.Issuer.String(), 256),
			NotBefore:         cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
			DNSNames: append([]string(nil), dnsNames...), IPAddresses: ipStrings,
		})
	}
	return descriptions
}

func makeTLSFinding(host, canonical, ruleID, title, severity, description, remediation string, discovered time.Time) (json.RawMessage, error) {
	u, err := url.Parse(canonical)
	if err != nil {
		return nil, err
	}
	u.RawQuery, u.ForceQuery, u.Fragment = "", false, ""
	endpoint := u.String()
	finding := map[string]any{
		"schema_version": "1.0", "title": title, "severity": severity, "confidence": 1.0,
		"target":        map[string]any{"asset": host, "endpoint": endpoint},
		"vulnerability": map[string]any{"template_id": ruleID},
		"description":   description, "remediation": map[string]any{"summary": remediation},
		"scanner":       map[string]any{"name": ScannerTLSAssessor, "adapter_version": "1.0.0"},
		"discovered_at": discovered.UTC().Format(time.RFC3339Nano),
		"tags":          []string{"tls", "configuration"},
	}
	raw, err := json.Marshal(finding)
	if err != nil {
		return nil, err
	}
	if err := ValidateFindings(raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func isWeakTLSCipher(name string) bool {
	name = strings.ToUpper(name)
	return strings.Contains(name, "_CBC_") || strings.Contains(name, "RC4") || strings.Contains(name, "3DES") || strings.Contains(name, "_NULL_")
}

func classifyTLSAttemptError(err error, ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "cancelled"
	}
	message := strings.ToLower(err.Error())
	if strings.Contains(message, "protocol version") || strings.Contains(message, "no supported versions") {
		return "unsupported"
	}
	return "handshake_failed"
}

func isCertificateValidityError(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Reason == x509.Expired
}

func boundedString(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}

func tlsAssessmentConfig(task Task) (ScannerConfigV1, error) {
	if len(task.Payload) == 0 || strings.TrimSpace(string(task.Payload)) == "null" {
		return DefaultScannerConfig(ScannerTLSAssessor)
	}
	config, err := DecodeScannerConfig(task.Payload)
	if err != nil {
		return ScannerConfigV1{}, err
	}
	if config.ScannerID != ScannerTLSAssessor {
		return ScannerConfigV1{}, fmt.Errorf("adapters: TLS assessment received config for scanner %q", config.ScannerID)
	}
	return config, nil
}

func intPointer(value int) *int { return &value }

func minTLSAssessmentDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

var _ ScannerAdapter = (*TLSAssessmentAdapter)(nil)
