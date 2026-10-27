package validation

import "testing"

func TestIsUUIDV4(t *testing.T) {
	valid := []string{"6b8e1a40-9f2d-4c1e-8a7b-3d5f0c2e9b11", "00000000-0000-4000-8000-000000000000"}
	invalid := []string{
		"",
		"6B8E1A40-9F2D-4C1E-8A7B-3D5F0C2E9B11",
		"6b8e1a409f2d4c1e8a7b3d5f0c2e9b11",
		"6b8e1a40-9f2d-1c1e-8a7b-3d5f0c2e9b11",
		"not-a-uuid",
	}
	for _, s := range valid {
		if !IsUUIDV4(s) {
			t.Errorf("IsUUIDV4(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if IsUUIDV4(s) {
			t.Errorf("IsUUIDV4(%q) = true, want false", s)
		}
	}
}

func TestIsCorrelationIDMatchesHeaderContract(t *testing.T) {
	if !IsCorrelationID("abc-123") || !IsCorrelationID("3f1c9a72-5d84-4e0b-9c6a-1b7e2d4f8a55") {
		t.Fatal("standard values must pass")
	}
	if IsCorrelationID("") || IsCorrelationID(string(make([]byte, 129))) || IsCorrelationID("bad id!") {
		t.Fatal("out-of-contract values must fail")
	}
}

func TestIsWireEnum(t *testing.T) {
	if !IsWireEnum("QUEUED") || !IsWireEnum("TIMED_OUT") {
		t.Fatal("wire enums must pass")
	}
	if IsWireEnum("queued") || IsWireEnum("In Progress") {
		t.Fatal("non-enum shapes must fail")
	}
}

func TestIsRFC3339UTC(t *testing.T) {
	if !IsRFC3339UTC("2026-10-26T14:30:00Z") {
		t.Fatal("Z-suffix timestamp must pass")
	}
	if IsRFC3339UTC("2026-10-26T14:30:00+02:00") || IsRFC3339UTC("2026-10-26 14:30:00") {
		t.Fatal("offset or non-RFC3339 timestamps must fail")
	}
}

func TestOneOf(t *testing.T) {
	if !OneOf("HIGH", "LOW", "MEDIUM", "HIGH", "CRITICAL") {
		t.Fatal("member must pass")
	}
	if OneOf("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") {
		t.Fatal("non-member must fail")
	}
}
