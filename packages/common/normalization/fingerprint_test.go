package normalization

import (
	"encoding/json"
	"os"
	"testing"
)

type vectorFile struct {
	Algorithm string `json:"algorithm"`
	Vectors   []struct {
		Name          string  `json:"name"`
		Asset         string  `json:"asset"`
		Endpoint      *string `json:"endpoint"`
		Vulnerability struct {
			TemplateID string   `json:"template_id"`
			CVEIDs     []string `json:"cve_ids"`
			CWEID      string   `json:"cwe_id"`
			Title      string   `json:"title"`
		} `json:"vulnerability"`
		ExpectedVulnKey     string `json:"expected_vulnerability_key"`
		ExpectedCanonical   string `json:"expected_canonical"`
		ExpectedFingerprint string `json:"expected_fingerprint"`
	} `json:"vectors"`
}

func TestFingerprintNormativeVectorsCommon(t *testing.T) {
	fixturePath := "../../../packages/schemas/fixtures/fingerprint-vectors.json"
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("could not read test vectors file: %v", err)
	}

	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("unmarshal vector file: %v", err)
	}

	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			endpointStr := ""
			if v.Endpoint != nil {
				endpointStr = *v.Endpoint
			}

			vulnKey := DeriveVulnerabilityKey(
				v.Vulnerability.TemplateID,
				v.Vulnerability.CVEIDs,
				v.Vulnerability.CWEID,
				v.Vulnerability.Title,
			)
			if vulnKey != v.ExpectedVulnKey {
				t.Errorf("vulnKey mismatch: got %q, want %q", vulnKey, v.ExpectedVulnKey)
			}

			res, err := GenerateFingerprint(FingerprintInput{
				Asset:      v.Asset,
				Endpoint:   endpointStr,
				TemplateID: v.Vulnerability.TemplateID,
				CVEIDs:     v.Vulnerability.CVEIDs,
				CWEID:      v.Vulnerability.CWEID,
				Title:      v.Vulnerability.Title,
				Algorithm:  AlgorithmV1,
			})
			if err != nil {
				t.Fatalf("GenerateFingerprint failed: %v", err)
			}

			if res.Canonical != v.ExpectedCanonical {
				t.Errorf("canonical mismatch:\ngot:  %q\nwant: %q", res.Canonical, v.ExpectedCanonical)
			}

			if res.Digest != v.ExpectedFingerprint {
				t.Errorf("fingerprint digest mismatch:\ngot:  %q\nwant: %q", res.Digest, v.ExpectedFingerprint)
			}

			// Verify tagged ID format: fp_v1_<digest>
			expectedTagged := "fp_v1_" + v.ExpectedFingerprint
			if res.TaggedID != expectedTagged {
				t.Errorf("tagged ID mismatch: got %q, want %q", res.TaggedID, expectedTagged)
			}
		})
	}
}

func TestEndpointNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "standard http default port 80 omitted",
			input:    "http://example.com:80/path/test",
			expected: "http://example.com/path/test",
		},
		{
			name:     "standard https default port 443 omitted",
			input:    "https://example.com:443/login",
			expected: "https://example.com/login",
		},
		{
			name:     "custom port preserved",
			input:    "http://example.com:8080/api/v1",
			expected: "http://example.com:8080/api/v1",
		},
		{
			name:     "path cleaned and normalized",
			input:    "https://example.com/a/b/../c/./d/",
			expected: "https://example.com/a/c/d",
		},
		{
			name:     "percent encoding uppercased",
			input:    "https://example.com/path%2fa%20b",
			expected: "https://example.com/path%2Fa%20b",
		},
		{
			name:     "empty endpoint returns empty without error",
			input:    "",
			expected: "",
		},
		{
			name:    "unsupported scheme returns error",
			input:   "ftp://example.com/file",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeEndpoint(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("NormalizeEndpoint(%q) err = %v, wantErr = %v", tc.input, err, tc.wantErr)
			}
			if got != tc.expected {
				t.Errorf("NormalizeEndpoint(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestAlgorithmVersioningAndParameters(t *testing.T) {
	inV1 := FingerprintInput{
		Asset:      "api.example.com",
		Endpoint:   "https://api.example.com/users",
		TemplateID: "cve-2023-1234",
		Parameter:  "user_id",
		Algorithm:  AlgorithmV1,
	}

	resV1, err := GenerateFingerprint(inV1)
	if err != nil {
		t.Fatalf("GenerateFingerprint v1 failed: %v", err)
	}

	inV2Param1 := FingerprintInput{
		Asset:      "api.example.com",
		Endpoint:   "https://api.example.com/users",
		TemplateID: "cve-2023-1234",
		Parameter:  "USER_ID",
		Algorithm:  AlgorithmV2,
	}

	resV2Param1, err := GenerateFingerprint(inV2Param1)
	if err != nil {
		t.Fatalf("GenerateFingerprint v2 failed: %v", err)
	}

	inV2Param2 := FingerprintInput{
		Asset:      "api.example.com",
		Endpoint:   "https://api.example.com/users",
		TemplateID: "cve-2023-1234",
		Parameter:  "role",
		Algorithm:  AlgorithmV2,
	}

	resV2Param2, err := GenerateFingerprint(inV2Param2)
	if err != nil {
		t.Fatalf("GenerateFingerprint v2 param2 failed: %v", err)
	}

	// v1 and v2 should produce different digests for the same core fields
	if resV1.Digest == resV2Param1.Digest {
		t.Errorf("v1 and v2 digests should differ due to algorithm version prefix")
	}

	// v2 with case-insensitive parameter normalization should match
	inV2Param1Lower := inV2Param1
	inV2Param1Lower.Parameter = "user_id"
	resV2Param1Lower, err := GenerateFingerprint(inV2Param1Lower)
	if err != nil {
		t.Fatalf("GenerateFingerprint v2 lower failed: %v", err)
	}
	if resV2Param1.Digest != resV2Param1Lower.Digest {
		t.Errorf("v2 parameters should be case-normalized: %q != %q", resV2Param1.Digest, resV2Param1Lower.Digest)
	}

	// v2 with different parameters should produce different digests
	if resV2Param1.Digest == resV2Param2.Digest {
		t.Errorf("v2 with different parameters should produce different digests")
	}
}

func TestTaggedFingerprintParsing(t *testing.T) {
	tagged := "fp_v1_d3b07384d113edec49eaa6238ad5ff00b7d8536f9479b47e8e5033878b277ff1"
	ver, digest, err := ParseTaggedFingerprint(tagged)
	if err != nil {
		t.Fatalf("ParseTaggedFingerprint failed: %v", err)
	}
	if ver != "v1" {
		t.Errorf("version mismatch: got %q, want v1", ver)
	}
	if digest != "d3b07384d113edec49eaa6238ad5ff00b7d8536f9479b47e8e5033878b277ff1" {
		t.Errorf("digest mismatch: got %q", digest)
	}

	_, _, err = ParseTaggedFingerprint("invalid-format")
	if err == nil {
		t.Errorf("expected error for invalid tagged fingerprint format")
	}
}

func TestAmbiguityDetection(t *testing.T) {
	// Same asset and rule, different endpoints -> ambiguous
	if !IsAmbiguousIdentity("app.example.com", "https://app.example.com/api/v1", "cwe-79", "app.example.com", "https://app.example.com/api/v2", "cwe-79") {
		t.Errorf("expected ambiguous identity for same asset/cwe but different endpoints")
	}

	// Different assets -> not ambiguous
	if IsAmbiguousIdentity("app1.example.com", "https://app1.example.com/api", "cwe-79", "app2.example.com", "https://app2.example.com/api", "cwe-79") {
		t.Errorf("expected non-ambiguous for different assets")
	}

	// Different vulnerabilities -> not ambiguous
	if IsAmbiguousIdentity("app.example.com", "https://app.example.com/api", "cwe-79", "app.example.com", "https://app.example.com/api", "cwe-89") {
		t.Errorf("expected non-ambiguous for different vulnerability keys")
	}
}

