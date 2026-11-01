package schemas

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

func TestFindingV1Embedded(t *testing.T) {
	raw := MustRead("finding.v1.json")
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("finding.v1.json is not valid JSON: %v", err)
	}
	if id, _ := schema["$id"].(string); id != "urn:kelvin:schemas:finding.v1.json" {
		t.Fatalf("unexpected $id: %q", id)
	}
}

func TestEnvelopeAndProblemSchemasEmbedded(t *testing.T) {
	for _, name := range []string{"api-envelope.schema.json", "api-error.schema.json"} {
		if _, err := Read(name); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}
}

func TestScannerOutputSchemaEmbedded(t *testing.T) {
	raw := MustRead("scanner-output.v1.json")
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("scanner-output.v1.json is not valid JSON: %v", err)
	}
	if id, _ := schema["$id"].(string); id != "https://kelvin.security/schema/scanner-output/v1" {
		t.Fatalf("unexpected scanner output schema id: %q", id)
	}
}

func TestFixturesEmbedded(t *testing.T) {
	count := 0
	err := fs.WalkDir(FS(), "fixtures", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		count++
		if !strings.HasSuffix(path, ".json") {
			t.Errorf("unexpected non-JSON fixture: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count < 9 {
		t.Fatalf("expected at least 9 embedded fixtures, found %d", count)
	}
}
