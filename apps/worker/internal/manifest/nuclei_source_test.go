package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	hex40Regex  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Regex = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func TestNucleiSourceVerification_IntegrityAndToolchain(t *testing.T) {
	envPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei", "source.env")
	jsonPath := filepath.Join("..", "..", "..", "..", "deploy", "scanners", "nuclei", "source-provenance.json")

	// 1. Verify source.env exists and has required invariants
	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("failed to read source.env: %v", err)
	}

	lines := strings.Split(string(data), "\n")
	envMap := make(map[string]string)
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		parts := strings.SplitN(l, "=", 2)
		if len(parts) == 2 {
			envMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	commit := envMap["NUCLEI_SOURCE_COMMIT"]
	if !hex40Regex.MatchString(commit) {
		t.Fatalf("expected valid 40-hex commit hash, got %q", commit)
	}

	tag := envMap["NUCLEI_SOURCE_TAG"]
	if tag != "v3.11.1" {
		t.Fatalf("expected source tag v3.11.1, got %q", tag)
	}

	builderDigest := envMap["GOLANG_BUILDER_DIGEST"]
	if !sha256Regex.MatchString(builderDigest) {
		t.Fatalf("expected valid sha256 builder digest, got %q", builderDigest)
	}

	runtimeDigest := envMap["DISTROLESS_RUNTIME_DIGEST"]
	if !sha256Regex.MatchString(runtimeDigest) {
		t.Fatalf("expected valid sha256 distroless digest, got %q", runtimeDigest)
	}

	// 2. Verify source-provenance.json consistency
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("failed to read source-provenance.json: %v", err)
	}

	var prov struct {
		Release struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
			Tag     string `json:"tag"`
		} `json:"release"`
		Builder struct {
			Image         string   `json:"image"`
			Digest        string   `json:"digest"`
			Architectures []string `json:"architectures"`
		} `json:"builder"`
		Runtime struct {
			Digest string `json:"digest"`
		} `json:"runtime"`
	}

	if err := json.Unmarshal(jsonData, &prov); err != nil {
		t.Fatalf("failed to parse source-provenance.json: %v", err)
	}

	if prov.Release.Commit != commit {
		t.Errorf("commit mismatch: env has %s, json has %s", commit, prov.Release.Commit)
	}
	if prov.Builder.Digest != builderDigest {
		t.Errorf("builder digest mismatch: env has %s, json has %s", builderDigest, prov.Builder.Digest)
	}
	if prov.Runtime.Digest != runtimeDigest {
		t.Errorf("runtime digest mismatch: env has %s, json has %s", runtimeDigest, prov.Runtime.Digest)
	}

	// 3. Confirm ARM64 and AMD64 multi-arch support
	hasArm64, hasAmd64 := false, false
	for _, arch := range prov.Builder.Architectures {
		if arch == "arm64" {
			hasArm64 = true
		}
		if arch == "amd64" {
			hasAmd64 = true
		}
	}
	if !hasArm64 || !hasAmd64 {
		t.Errorf("builder must support both arm64 and amd64, got %v", prov.Builder.Architectures)
	}
}

func TestNucleiSourceVerification_TamperDetection(t *testing.T) {
	// Negative test: verify that mutable branches or invalid digests fail validation
	invalidCommits := []string{
		"main",
		"dev",
		"v3.11.1",
		"not-a-sha",
		"123456",
	}

	for _, c := range invalidCommits {
		if hex40Regex.MatchString(c) {
			t.Errorf("expected commit %q to be rejected as non-hex40", c)
		}
	}

	invalidDigests := []string{
		"latest",
		"sha256:123",
		"md5:d41d8cd98f00b204e9800998ecf8427e",
	}

	for _, d := range invalidDigests {
		if sha256Regex.MatchString(d) {
			t.Errorf("expected digest %q to be rejected as invalid sha256", d)
		}
	}
}
