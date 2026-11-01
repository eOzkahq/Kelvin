package adapters

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/packages/common/scope"
	"go.uber.org/zap"
)

const HTTPHeaderRuleSetVersion = "kelvin.http_headers.rules.v1"

// HTTPSecurityHeadersAdapter evaluates response security headers and cookie
// attributes. It uses one bounded HEAD request and never reads the response
// body. Redirects are handled by the shared scope-enforcing HTTP client.
type HTTPSecurityHeadersAdapter struct {
	*ReferenceAdapter
	policyForTask ScopePolicyProvider
	rateMu        sync.Mutex
	nextRequest   time.Time
}

func NewHTTPSecurityHeadersAdapter(policyForTask ScopePolicyProvider) *HTTPSecurityHeadersAdapter {
	adapter := &HTTPSecurityHeadersAdapter{
		ReferenceAdapter: &ReferenceAdapter{
			AdapterName: ScannerHTTPHeaders,
			Caps: Capabilities{
				CheckCategories:      []string{"http_security_headers", "http_cookie_attributes"},
				SupportedTargetTypes: []string{"url"}, SupportedProtocols: []string{"http", "https"},
				PassiveOnly: true, RequiresNetwork: true, SupportsCancel: true,
				MaxConcurrency: 1, MaxRequestRate: 2, MaxRequests: scope.MaxRedirectHops + 1,
			},
		},
		policyForTask: policyForTask,
	}
	adapter.Run = adapter.run
	return adapter
}

func (a *HTTPSecurityHeadersAdapter) Initialize(ctx context.Context, logger *zap.Logger) error {
	if a.policyForTask == nil {
		return fmt.Errorf("adapters: HTTP security header assessment requires a trusted scope policy provider")
	}
	return a.ReferenceAdapter.Initialize(ctx, logger)
}

func (a *HTTPSecurityHeadersAdapter) ValidateConfig(raw json.RawMessage) error {
	config, err := httpHeadersConfig(Task{Scanner: ScannerHTTPHeaders, Payload: raw})
	if err != nil {
		return err
	}
	if config.RequestsPerSecond > a.Capabilities().MaxRequestRate || config.MaxConcurrency > a.Capabilities().MaxConcurrency {
		return fmt.Errorf("adapters: HTTP security header config exceeds adapter request or concurrency limits")
	}
	return nil
}

func (a *HTTPSecurityHeadersAdapter) run(ctx context.Context, task Task) (Result, error) {
	config, err := httpHeadersConfig(task)
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
		return Result{}, fmt.Errorf("adapters: HTTP header target rejected by scope policy: %w", err)
	}
	approvedURL, err := url.Parse(target.Canonical)
	if err != nil || approvedURL == nil || (approvedURL.Scheme != "http" && approvedURL.Scheme != "https") {
		return Result{}, fmt.Errorf("adapters: HTTP header assessment requires an approved HTTP or HTTPS URL")
	}
	if err := a.waitForRequestSlot(operationCtx, config.RequestsPerSecond); err != nil {
		return Result{}, err
	}
	requestTimeout := minTLSAssessmentDuration(time.Duration(config.RequestTimeoutSeconds)*time.Second, deadline)
	requestCtx, requestCancel := context.WithTimeout(operationCtx, requestTimeout)
	defer requestCancel()
	client := policy.NewHTTPClient()
	client.Timeout = requestTimeout
	if pinned, ok := client.Transport.(*scope.PinnedTransport); ok {
		pinned.Base = &http.Transport{
			Proxy: nil, TLSHandshakeTimeout: requestTimeout, ResponseHeaderTimeout: requestTimeout,
			MaxResponseHeaderBytes: 64 << 10, DisableKeepAlives: true,
		}
	}
	request, err := http.NewRequestWithContext(requestCtx, http.MethodHead, approvedURL.String(), nil)
	if err != nil {
		return Result{}, fmt.Errorf("adapters: build HTTP header request: %w", err)
	}
	request.Header.Set("User-Agent", "Kelvin-HTTP-Headers/1.0")
	request.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
	response, requestErr := client.Do(request)
	completed := time.Now().UTC()
	if requestErr != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return a.finishHTTPHeadersFailure(task, target.Canonical, started, completed, requestCtx, requestErr)
	}
	defer response.Body.Close()
	finalURL := approvedURL
	redirected := false
	if response.Request != nil && response.Request.URL != nil {
		finalURL = response.Request.URL
		redirected = finalURL.String() != target.Canonical
	}
	findings, err := evaluateHTTPSecurityHeaders(finalURL.Hostname(), finalURL, response, completed)
	if err != nil {
		return Result{}, err
	}
	observation, err := json.Marshal(httpHeadersObservation{
		Outcome: "HTTP_RESPONDED", Target: target.Canonical, FinalURL: stripURLQuery(finalURL),
		StatusCode: response.StatusCode, Protocol: response.Proto, Redirected: redirected,
		ContentType:    boundedString(response.Header.Get("Content-Type"), 256),
		RuleSetVersion: HTTPHeaderRuleSetVersion,
	})
	if err != nil {
		return Result{}, fmt.Errorf("adapters: encode HTTP header observation: %w", err)
	}
	ruleVersion, _ := json.Marshal(HTTPHeaderRuleSetVersion)
	return Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID: task.AssessmentID, ScannerID: ScannerHTTPHeaders,
			ScannerVersion: a.Version(), AdapterVersion: a.Version(), RunID: uuid.NewString(),
			StartedAt: started, CompletedAt: completed, CorrelationID: task.CorrelationID,
		},
		Status: StatusCompleted, ExitCode: intPointer(0), DurationMS: time.Since(started).Milliseconds(),
		Findings: findings, Diagnostics: []ExecutionDiagnostic{},
		ScannerMetadata: map[string]json.RawMessage{
			"http_headers.observation": observation, "http_headers.rule_set_version": ruleVersion,
		},
		RawArtifacts: RawArtifactReferences{},
	}, nil
}

func (a *HTTPSecurityHeadersAdapter) finishHTTPHeadersFailure(task Task, target string, started, completed time.Time, ctx context.Context, cause error) (Result, error) {
	status, level, code, message := StatusCompletedWithWarnings, "warning", "HTTP_REQUEST_FAILED", "HTTP header response could not be obtained"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		status, level, code, message = StatusTimedOut, "error", "DEADLINE_EXCEEDED", "HTTP header request exceeded its configured timeout"
	} else if errors.Is(ctx.Err(), context.Canceled) {
		status, level, code, message = StatusCancelled, "error", "CANCELLED", "HTTP header request was cancelled"
	} else {
		code, message = preflightRedirectDiagnostic(cause)
	}
	observation, _ := json.Marshal(httpHeadersObservation{
		Outcome: "HTTP_FAILED", Target: target, Error: classifyPreflightError(ctx, cause),
		RuleSetVersion: HTTPHeaderRuleSetVersion,
	})
	ruleVersion, _ := json.Marshal(HTTPHeaderRuleSetVersion)
	return Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID: task.AssessmentID, ScannerID: ScannerHTTPHeaders,
			ScannerVersion: a.Version(), AdapterVersion: a.Version(), RunID: uuid.NewString(),
			StartedAt: started, CompletedAt: completed, CorrelationID: task.CorrelationID,
		},
		Status: status, ExitCode: intPointer(0), DurationMS: time.Since(started).Milliseconds(),
		Findings: []json.RawMessage{}, Diagnostics: []ExecutionDiagnostic{{Level: level, Code: code, Message: message}},
		ScannerMetadata: map[string]json.RawMessage{
			"http_headers.observation": observation, "http_headers.rule_set_version": ruleVersion,
		},
		RawArtifacts: RawArtifactReferences{},
	}, nil
}

func (a *HTTPSecurityHeadersAdapter) waitForRequestSlot(ctx context.Context, requestsPerSecond int) error {
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

type httpHeadersObservation struct {
	Outcome        string `json:"outcome"`
	Target         string `json:"target"`
	FinalURL       string `json:"final_url,omitempty"`
	StatusCode     int    `json:"status_code,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Redirected     bool   `json:"redirected"`
	ContentType    string `json:"content_type,omitempty"`
	RuleSetVersion string `json:"rule_set_version"`
	Error          string `json:"error,omitempty"`
}

type headerEvidence struct {
	Type            string   `json:"type"`
	ContentType     string   `json:"content_type"`
	ContentRedacted string   `json:"content_redacted"`
	RedactedFields  []string `json:"redacted_fields"`
}

func evaluateHTTPSecurityHeaders(host string, finalURL *url.URL, response *http.Response, observedAt time.Time) ([]json.RawMessage, error) {
	findings := make([]json.RawMessage, 0)
	seen := make(map[string]bool)
	add := func(rule, title, severity, description, remediation string, confidence float64, evidence []headerEvidence) error {
		if seen[rule] {
			return nil
		}
		contextLine := fmt.Sprintf("HTTP status: %d; Content-Type: %s\n", response.StatusCode, boundedString(response.Header.Get("Content-Type"), 256))
		for i := range evidence {
			evidence[i].ContentRedacted = contextLine + evidence[i].ContentRedacted
		}
		finding, err := makeHTTPHeaderFinding(host, finalURL, rule, title, severity, description, remediation, confidence, evidence, observedAt)
		if err != nil {
			return err
		}
		seen[rule] = true
		findings = append(findings, finding)
		return nil
	}
	if finalURL.Scheme == "https" && !hasValidHSTS(response.Header.Values("Strict-Transport-Security")) {
		if err := add("kelvin.http_headers.hsts_missing", "HSTS is missing or invalid", "MEDIUM",
			"The HTTPS response did not contain exactly one valid Strict-Transport-Security policy with a positive max-age.",
			"Serve a valid Strict-Transport-Security header with a positive max-age over HTTPS.", 0.9,
			[]headerEvidence{headerEvidenceFor("Strict-Transport-Security", response.Header.Values("Strict-Transport-Security"))}); err != nil {
			return nil, err
		}
	}
	contentType := strings.ToLower(response.Header.Get("Content-Type"))
	isHTML := strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml")
	cspValues := response.Header.Values("Content-Security-Policy")
	if isHTML {
		if len(cspValues) == 0 {
			if err := add("kelvin.http_headers.csp_missing", "Content Security Policy is missing", "MEDIUM",
				"The HTML response did not include a Content-Security-Policy header.",
				"Define a Content Security Policy appropriate for the application's scripts, styles, and resources.", 0.75,
				[]headerEvidence{{Type: "HEADER_DUMP", ContentType: "text/plain", ContentRedacted: "Content-Security-Policy: <missing>", RedactedFields: []string{}}}); err != nil {
				return nil, err
			}
		} else if cspHasUnsafeScriptSources(cspValues) {
			if err := add("kelvin.http_headers.csp_unsafe_script", "Content Security Policy permits unsafe script sources", "MEDIUM",
				"The HTML response's Content-Security-Policy allows unsafe-inline without a nonce/hash or allows unsafe-eval.",
				"Remove unsafe-inline and unsafe-eval where possible; use per-response nonces or hashes for inline scripts.", 0.8,
				[]headerEvidence{{Type: "HEADER_DUMP", ContentType: "text/plain", ContentRedacted: cspSummary(cspValues), RedactedFields: []string{}}}); err != nil {
				return nil, err
			}
		}
	}
	if response.Header.Get("Content-Type") != "" && !strings.EqualFold(strings.TrimSpace(response.Header.Get("X-Content-Type-Options")), "nosniff") {
		if err := add("kelvin.http_headers.content_type_options", "X-Content-Type-Options nosniff is missing", "LOW",
			"The response did not set X-Content-Type-Options to nosniff.",
			"Set X-Content-Type-Options: nosniff to prevent MIME sniffing.", 0.85,
			[]headerEvidence{headerEvidenceFor("X-Content-Type-Options", response.Header.Values("X-Content-Type-Options"))}); err != nil {
			return nil, err
		}
	}
	if isHTML {
		if !hasFrameProtection(response.Header.Values("X-Frame-Options"), cspValues) {
			if err := add("kelvin.http_headers.frame_protection", "HTML response lacks framing protection", "MEDIUM",
				"The HTML response has no effective X-Frame-Options or CSP frame-ancestors restriction.",
				"Set X-Frame-Options to DENY or SAMEORIGIN, or define a restrictive CSP frame-ancestors directive.", 0.75,
				[]headerEvidence{{Type: "HEADER_DUMP", ContentType: "text/plain", ContentRedacted: frameProtectionSummary(response.Header.Values("X-Frame-Options"), cspValues), RedactedFields: []string{}}}); err != nil {
				return nil, err
			}
		}
		if !hasSafeReferrerPolicy(response.Header.Values("Referrer-Policy")) {
			if err := add("kelvin.http_headers.referrer_policy", "Referrer Policy is missing or weak", "LOW",
				"The HTML response did not specify a recognized restrictive Referrer-Policy.",
				"Set Referrer-Policy to no-referrer, same-origin, strict-origin, or strict-origin-when-cross-origin.", 0.8,
				[]headerEvidence{headerEvidenceFor("Referrer-Policy", response.Header.Values("Referrer-Policy"))}); err != nil {
				return nil, err
			}
		}
		if hasUnrestrictedSensitivePermission(response.Header.Values("Permissions-Policy")) {
			if err := add("kelvin.http_headers.permissions_policy", "Permissions Policy allows sensitive features to all origins", "MEDIUM",
				"The response explicitly allows camera, microphone, or geolocation access to all origins.",
				"Restrict sensitive browser features to the origins that require them, or disable them.", 0.85,
				[]headerEvidence{{Type: "HEADER_DUMP", ContentType: "text/plain", ContentRedacted: permissionsPolicySummary(response.Header.Values("Permissions-Policy")), RedactedFields: []string{}}}); err != nil {
				return nil, err
			}
		}
	}
	if finalURL.Scheme == "https" {
		var missingSecure, missingHTTPOnly, missingSameSite []http.Cookie
		for _, cookie := range response.Cookies() {
			if !cookie.Secure {
				missingSecure = append(missingSecure, *cookie)
			}
			if !cookie.HttpOnly {
				missingHTTPOnly = append(missingHTTPOnly, *cookie)
			}
			if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 || (cookie.SameSite == http.SameSiteNoneMode && !cookie.Secure) {
				missingSameSite = append(missingSameSite, *cookie)
			}
		}
		if len(missingSecure) > 0 {
			if err := add("kelvin.http_headers.cookie_secure", "Cookie Secure attribute is missing", "MEDIUM",
				fmt.Sprintf("%d cookie(s) returned over HTTPS omitted the Secure attribute.", len(missingSecure)),
				"Set Secure on cookies that should only be sent over HTTPS.", 0.9, cookieEvidence(missingSecure)); err != nil {
				return nil, err
			}
		}
		if len(missingHTTPOnly) > 0 {
			if err := add("kelvin.http_headers.cookie_httponly", "Cookie HttpOnly attribute is missing", "LOW",
				fmt.Sprintf("%d cookie(s) did not set HttpOnly; client-side access may be intentional for some cookies.", len(missingHTTPOnly)),
				"Set HttpOnly on session and other sensitive cookies that do not need client-side script access.", 0.65, cookieEvidence(missingHTTPOnly)); err != nil {
				return nil, err
			}
		}
		if len(missingSameSite) > 0 {
			if err := add("kelvin.http_headers.cookie_samesite", "Cookie SameSite attribute is missing or inconsistent", "LOW",
				fmt.Sprintf("%d cookie(s) omitted SameSite or used SameSite=None without Secure.", len(missingSameSite)),
				"Set SameSite=Lax or Strict where cross-site use is not required; SameSite=None requires Secure.", 0.7, cookieEvidence(missingSameSite)); err != nil {
				return nil, err
			}
		}
	}
	return findings, nil
}

func makeHTTPHeaderFinding(host string, endpoint *url.URL, rule, title, severity, description, remediation string, confidence float64, evidence []headerEvidence, discovered time.Time) (json.RawMessage, error) {
	finding := map[string]any{
		"schema_version": "1.0", "title": title, "severity": severity, "confidence": confidence,
		"target":        map[string]any{"asset": host, "endpoint": stripURLQuery(endpoint)},
		"vulnerability": map[string]any{"template_id": rule}, "description": description,
		"remediation":   map[string]any{"summary": remediation},
		"evidence":      evidence,
		"scanner":       map[string]any{"name": ScannerHTTPHeaders, "adapter_version": "1.0.0"},
		"discovered_at": discovered.UTC().Format(time.RFC3339Nano), "tags": []string{"http", "security-headers"},
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

func hasValidHSTS(values []string) bool {
	if len(values) != 1 {
		return false
	}
	maxAge := int64(-1)
	for _, directive := range strings.Split(values[0], ";") {
		name, value, hasValue := strings.Cut(strings.TrimSpace(directive), "=")
		if strings.EqualFold(strings.TrimSpace(name), "max-age") && hasValue {
			parsed, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(value), "\""), 10, 64)
			if err != nil || parsed < 1 {
				return false
			}
			if maxAge >= 0 {
				return false
			}
			maxAge = parsed
		}
	}
	return maxAge > 0
}

func cspHasUnsafeScriptSources(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ";") {
			fields := strings.Fields(strings.ToLower(strings.TrimSpace(directive)))
			if len(fields) == 0 || (fields[0] != "script-src" && fields[0] != "script-src-elem") {
				continue
			}
			unsafeEval, unsafeInline, nonceOrHash := false, false, false
			for _, source := range fields[1:] {
				unsafeEval = unsafeEval || source == "'unsafe-eval'"
				unsafeInline = unsafeInline || source == "'unsafe-inline'"
				nonceOrHash = nonceOrHash || strings.HasPrefix(source, "'nonce-") || strings.HasPrefix(source, "'sha256-") || strings.HasPrefix(source, "'sha384-") || strings.HasPrefix(source, "'sha512-")
			}
			if unsafeEval || (unsafeInline && !nonceOrHash) {
				return true
			}
		}
	}
	return false
}

func hasFrameProtection(xfoValues, cspValues []string) bool {
	for _, value := range xfoValues {
		if strings.EqualFold(strings.TrimSpace(value), "DENY") || strings.EqualFold(strings.TrimSpace(value), "SAMEORIGIN") {
			return true
		}
	}
	for _, value := range cspValues {
		for _, directive := range strings.Split(value, ";") {
			fields := strings.Fields(strings.ToLower(strings.TrimSpace(directive)))
			if len(fields) == 0 || fields[0] != "frame-ancestors" || len(fields) == 1 {
				continue
			}
			wildcard := false
			for _, source := range fields[1:] {
				wildcard = wildcard || source == "*" || source == "http:" || source == "https:"
			}
			if !wildcard {
				return true
			}
		}
	}
	return false
}

func hasSafeReferrerPolicy(values []string) bool {
	allowed := map[string]bool{"no-referrer": true, "same-origin": true, "strict-origin": true, "strict-origin-when-cross-origin": true}
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			if allowed[strings.ToLower(strings.TrimSpace(item))] {
				return true
			}
		}
	}
	return false
}

func hasUnrestrictedSensitivePermission(values []string) bool {
	for _, value := range values {
		for _, directive := range strings.Split(value, ",") {
			name, allowlist, ok := strings.Cut(strings.TrimSpace(directive), "=")
			name = strings.ToLower(strings.TrimSpace(name))
			if !ok || (name != "camera" && name != "microphone" && name != "geolocation") {
				continue
			}
			allowlist = strings.TrimSpace(allowlist)
			if allowlist == "*" || allowlist == "(*)" {
				return true
			}
		}
	}
	return false
}

func headerEvidenceFor(name string, values []string) headerEvidence {
	value := "<missing>"
	if len(values) > 0 {
		value = boundedString(strings.Join(values, "; "), 512)
	}
	return headerEvidence{Type: "HEADER_DUMP", ContentType: "text/plain", ContentRedacted: name + ": " + value, RedactedFields: []string{}}
}

func cspSummary(values []string) string {
	directives := make([]string, 0)
	unsafeInline, unsafeEval := false, false
	for _, value := range values {
		for _, directive := range strings.Split(value, ";") {
			fields := strings.Fields(strings.ToLower(strings.TrimSpace(directive)))
			if len(fields) == 0 {
				continue
			}
			directives = append(directives, fields[0])
			for _, source := range fields[1:] {
				unsafeInline = unsafeInline || source == "'unsafe-inline'"
				unsafeEval = unsafeEval || source == "'unsafe-eval'"
			}
		}
	}
	return fmt.Sprintf("Content-Security-Policy: present; directives=%s; unsafe-inline=%t; unsafe-eval=%t", strings.Join(directives, ","), unsafeInline, unsafeEval)
}

func frameProtectionSummary(xfoValues, cspValues []string) string {
	xfo := "<missing>"
	if len(xfoValues) > 0 {
		xfo = boundedString(strings.Join(xfoValues, ","), 256)
	}
	hasFrameAncestors := false
	for _, value := range cspValues {
		for _, directive := range strings.Split(value, ";") {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(directive)), "frame-ancestors") {
				hasFrameAncestors = true
			}
		}
	}
	return fmt.Sprintf("X-Frame-Options: %s; CSP frame-ancestors present: %t", xfo, hasFrameAncestors)
}

func permissionsPolicySummary(values []string) string {
	return "Permissions-Policy: " + boundedString(strings.Join(values, ","), 512)
}

func cookieEvidence(cookies []http.Cookie) []headerEvidence {
	if len(cookies) > 10 {
		cookies = cookies[:10]
	}
	evidence := make([]headerEvidence, 0, len(cookies))
	for _, cookie := range cookies {
		sameSite := "missing"
		switch cookie.SameSite {
		case http.SameSiteLaxMode:
			sameSite = "Lax"
		case http.SameSiteStrictMode:
			sameSite = "Strict"
		case http.SameSiteNoneMode:
			sameSite = "None"
		}
		content := fmt.Sprintf("Set-Cookie: <value redacted>; Secure=%t; HttpOnly=%t; SameSite=%s", cookie.Secure, cookie.HttpOnly, sameSite)
		evidence = append(evidence, headerEvidence{
			Type: "HEADER_DUMP", ContentType: "text/plain", ContentRedacted: content,
			RedactedFields: []string{"response.header.set-cookie.value"},
		})
	}
	return evidence
}

func stripURLQuery(value *url.URL) string {
	if value == nil {
		return ""
	}
	copyURL := *value
	copyURL.RawQuery, copyURL.ForceQuery, copyURL.Fragment = "", false, ""
	return copyURL.String()
}

func httpHeadersConfig(task Task) (ScannerConfigV1, error) {
	if len(task.Payload) == 0 || strings.TrimSpace(string(task.Payload)) == "null" {
		return DefaultScannerConfig(ScannerHTTPHeaders)
	}
	config, err := DecodeScannerConfig(task.Payload)
	if err != nil {
		return ScannerConfigV1{}, err
	}
	if config.ScannerID != ScannerHTTPHeaders {
		return ScannerConfigV1{}, fmt.Errorf("adapters: HTTP header assessment received config for scanner %q", config.ScannerID)
	}
	return config, nil
}

var _ ScannerAdapter = (*HTTPSecurityHeadersAdapter)(nil)
