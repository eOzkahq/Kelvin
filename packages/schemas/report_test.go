package schemas

import (
	"encoding/json"
	"testing"
)

func TestReportV1SchemaEmbedded(t *testing.T) {
	raw := MustRead("report.v1.json")
	var schema map[string]any
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatalf("report.v1.json is not valid JSON: %v", err)
	}
	if id, _ := schema["$id"].(string); id != "urn:kelvin:schemas:report.v1.json" {
		t.Fatalf("unexpected report schema id: %q", id)
	}
	if title, _ := schema["title"].(string); title != "Kelvin Customer-Facing Assessment Report v1" {
		t.Fatalf("unexpected report schema title: %q", title)
	}
}
