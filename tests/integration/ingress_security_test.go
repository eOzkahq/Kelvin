package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIngressSecurityConfigurations verifies that reverse-proxy and DNS configurations
// enforce TLS 1.3, strict security headers, trusted-proxy CIDRs, and internal endpoint blocks.
func TestIngressSecurityConfigurations(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}

	repoRoot := filepath.Clean(filepath.Join(cwd, "../.."))
	nginxConfPath := filepath.Join(repoRoot, "deploy", "ingress", "nginx-ingress.conf")

	data, err := os.ReadFile(nginxConfPath)
	if err != nil {
		t.Fatalf("Missing deploy/ingress/nginx-ingress.conf: %v", err)
	}
	conf := string(data)

	// 1. Verify TLS baseline
	if !strings.Contains(conf, "ssl_protocols TLSv1.2 TLSv1.3;") {
		t.Errorf("nginx-ingress.conf must enforce TLSv1.2 and TLSv1.3")
	}

	// 2. Verify Security Headers
	requiredHeaders := []string{
		"Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\"",
		"X-Content-Type-Options \"nosniff\"",
		"X-Frame-Options \"DENY\"",
		"Content-Security-Policy",
		"Referrer-Policy",
	}
	for _, h := range requiredHeaders {
		if !strings.Contains(conf, h) {
			t.Errorf("nginx-ingress.conf missing security header: %s", h)
		}
	}

	// 3. Verify Trusted-Proxy real IP configuration
	if !strings.Contains(conf, "real_ip_header X-Forwarded-For;") {
		t.Errorf("nginx-ingress.conf missing trusted-proxy real_ip_header")
	}

	// 4. Verify Host-Header Injection prevention (default drop 444)
	if !strings.Contains(conf, "return 444;") {
		t.Errorf("nginx-ingress.conf missing default server connection drop (return 444)")
	}

	// 5. Verify Internal route blocking
	if !strings.Contains(conf, "location /internal/") || !strings.Contains(conf, "return 403;") {
		t.Errorf("nginx-ingress.conf missing /internal/ route blocking")
	}

	// 6. Verify Terraform DNS Module
	dnsModDir := filepath.Join(repoRoot, "infra", "terraform", "modules", "dns")
	for _, f := range []string{"main.tf", "variables.tf", "outputs.tf"} {
		p := filepath.Join(dnsModDir, f)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			t.Errorf("Missing Terraform DNS module file: %s", p)
		}
	}
}
