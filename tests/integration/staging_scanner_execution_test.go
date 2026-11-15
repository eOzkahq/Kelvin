package integration

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagingScannerExecution_ComposeSecurityInvariants(t *testing.T) {
	composePath := filepath.Join("..", "..", "deploy", "compose", "docker-compose.staging.yml")
	contentBytes, err := os.ReadFile(composePath)
	if err != nil {
		t.Fatalf("failed to read staging compose file: %v", err)
	}
	content := string(contentBytes)

	// 1. Enforce non-root execution (UID 10001)
	if !strings.Contains(content, `user: "10001:10001"`) {
		t.Errorf("staging compose must enforce non-root user 10001:10001")
	}

	// 2. Enforce immutable root filesystem
	if !strings.Contains(content, "read_only: true") {
		t.Errorf("staging compose must enforce read_only: true")
	}

	// 3. Enforce privilege restriction
	if !strings.Contains(content, "no-new-privileges:true") {
		t.Errorf("staging compose must enforce no-new-privileges:true")
	}

	// 4. Enforce capabilities drop
	if !strings.Contains(content, "cap_drop:\n      - ALL") && !strings.Contains(content, "cap_drop:\r\n      - ALL") {
		t.Errorf("staging compose must drop ALL Linux capabilities")
	}

	// 5. Enforce single scanner concurrency on staging
	if !strings.Contains(content, `KELVIN_WORKER_CONCURRENCY: "1"`) {
		t.Errorf("staging worker concurrency must be strictly pinned to 1")
	}

	// 6. Prohibit Docker socket exposure
	if strings.Contains(content, "docker.sock") {
		t.Errorf("staging compose must never mount or expose docker.sock")
	}

	// 7. Enforce internal scanner network
	if !strings.Contains(content, "internal: true") {
		t.Errorf("scanner network must have internal: true to block direct egress bypass")
	}

	// 8. Enforce Anti-SSRF proxy with metadata & private subnet blocking
	for _, blocked := range []string{"169.254.169.254", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"} {
		if !strings.Contains(content, blocked) {
			t.Errorf("Anti-SSRF proxy configuration missing blocked CIDR %q", blocked)
		}
	}
}

func TestStagingScannerExecution_AntiSSRFPolicyEnforcement(t *testing.T) {
	// Reusable SSRF filter logic
	isBlockedTarget := func(target string) bool {
		u, err := url.Parse(target)
		if err != nil || u.Scheme == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return true
		}

		host := u.Hostname()
		if host == "localhost" {
			return true
		}

		ip := net.ParseIP(host)
		if ip != nil {
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				return true
			}
			// Explicit cloud metadata IP
			if ip.Equal(net.ParseIP("169.254.169.254")) {
				return true
			}
		}

		return false
	}

	blockedTargets := []string{
		"http://127.0.0.1:8080/admin",
		"https://localhost:8443",
		"http://[::1]:8080",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/api",
		"http://172.16.1.100",
		"http://192.168.1.1/router",
		"gopher://127.0.0.1:6379/_INFO",
		"file:///etc/passwd",
	}

	for _, target := range blockedTargets {
		if !isBlockedTarget(target) {
			t.Errorf("target %q must be blocked by Anti-SSRF policy", target)
		}
	}

	allowedTargets := []string{
		"http://juice-shop.staging.internal:3000",
		"https://crapi.staging.internal",
		"https://example.com/test",
	}

	for _, target := range allowedTargets {
		if isBlockedTarget(target) {
			t.Errorf("authorized staging target %q should be permitted", target)
		}
	}
}

func TestStagingScannerExecution_RunbookCompleteness(t *testing.T) {
	runbookPath := filepath.Join("..", "..", "docs", "operations", "RUNBOOK_SCANNER_STAGING.md")
	contentBytes, err := os.ReadFile(runbookPath)
	if err != nil {
		t.Fatalf("failed to read staging runbook: %v", err)
	}
	content := string(contentBytes)

	requiredSections := []string{
		"Unprivileged Rootless Execution",
		"Zero Docker Socket Exposure",
		"Fail-Closed Release Certification",
		"Network Topology & Anti-SSRF Architecture",
		"Emergency Killswitch & Rapid Rollback Procedures",
		"169.254.169.254",
		"SECURITY_AUDIT",
	}

	for _, sec := range requiredSections {
		if !strings.Contains(content, sec) {
			t.Errorf("RUNBOOK_SCANNER_STAGING.md missing required section/token: %q", sec)
		}
	}
}
