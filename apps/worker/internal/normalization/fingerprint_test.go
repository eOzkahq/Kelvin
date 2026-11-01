package normalization

import (
	"encoding/json"
	"testing"

	"github.com/kelvin/kelvin/packages/schemas"
)

type vectorFile struct {
	Algorithm string `json:"algorithm"`
	Vectors   []struct {
		Name                     string   `json:"name"`
		Asset                    string   `json:"asset"`
		Endpoint                 *string  `json:"endpoint"`
		Vulnerability            struct {
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

func TestFingerprintNormativeVectors(t *testing.T) {
	raw, err := schemas.Read("fixtures/fingerprint-vectors.json")
	if err != nil {
		t.Fatalf("could not read embedded vectors: %v", err)
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

			fp, canonical, err := ComputeFingerprint(
				v.Asset,
				endpointStr,
				v.Vulnerability.TemplateID,
				v.Vulnerability.CVEIDs,
				v.Vulnerability.CWEID,
				v.Vulnerability.Title,
			)
			if err != nil {
				t.Fatalf("ComputeFingerprint failed: %v", err)
			}

			if canonical != v.ExpectedCanonical {
				t.Errorf("canonical mismatch:\ngot:  %q\nwant: %q", canonical, v.ExpectedCanonical)
			}

			if fp != v.ExpectedFingerprint {
				t.Errorf("fingerprint mismatch:\ngot:  %q\nwant: %q", fp, v.ExpectedFingerprint)
			}
		})
	}
}
