package parserguard_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

func TestValidatePayload(t *testing.T) {
	t.Run("ValidPayload", func(t *testing.T) {
		err := parserguard.ValidatePayload([]byte(`{"status":"ok","findings":[]}`))
		if err != nil {
			t.Fatalf("unexpected error on valid payload: %v", err)
		}
	})

	t.Run("EmptyPayload", func(t *testing.T) {
		err := parserguard.ValidatePayload([]byte{})
		if !errors.Is(err, parserguard.ErrPayloadEmpty) {
			t.Fatalf("expected ErrPayloadEmpty, got: %v", err)
		}
	})

	t.Run("InvalidUTF8", func(t *testing.T) {
		malformed := []byte("invalid utf8 \xFF\xFE\xFD data")
		err := parserguard.ValidatePayload(malformed)
		if !errors.Is(err, parserguard.ErrInvalidUTF8) {
			t.Fatalf("expected ErrInvalidUTF8, got: %v", err)
		}
	})

	t.Run("NullByteInjection", func(t *testing.T) {
		nullInjected := []byte("null\x00byte")
		err := parserguard.ValidatePayload(nullInjected)
		if !errors.Is(err, parserguard.ErrContainsNullBytes) {
			t.Fatalf("expected ErrContainsNullBytes, got: %v", err)
		}
	})
}

func TestCheckJSONNestingDepth(t *testing.T) {
	t.Run("AcceptsShallowNesting", func(t *testing.T) {
		shallow := []byte(`{"a":{"b":{"c":[1,2,3]}}}`)
		if err := parserguard.CheckJSONNestingDepth(shallow, 32); err != nil {
			t.Fatalf("unexpected error on shallow JSON: %v", err)
		}
	})

	t.Run("RejectsDeepNestingExceedingMax", func(t *testing.T) {
		// Build 35 levels of nesting: {"n":{"n": ... }}
		depth := 35
		var sb strings.Builder
		for i := 0; i < depth; i++ {
			sb.WriteString(`{"nested":`)
		}
		sb.WriteString(`"innermost"`)
		for i := 0; i < depth; i++ {
			sb.WriteString(`}`)
		}

		err := parserguard.CheckJSONNestingDepth([]byte(sb.String()), 32)
		if !errors.Is(err, parserguard.ErrNestingDepthExceeded) {
			t.Fatalf("expected ErrNestingDepthExceeded on depth %d, got: %v", depth, err)
		}
	})

	t.Run("RejectsUnbalancedDelimiters", func(t *testing.T) {
		unbalanced := []byte(`{"a":{"b":1}}}`)
		err := parserguard.CheckJSONNestingDepth(unbalanced, 32)
		if err == nil {
			t.Fatalf("expected error on unbalanced delimiters")
		}
	})

	t.Run("RejectsIncompleteJSON", func(t *testing.T) {
		incomplete := []byte(`{"a":{"b":1`)
		err := parserguard.CheckJSONNestingDepth(incomplete, 32)
		if err == nil {
			t.Fatalf("expected error on incomplete JSON")
		}
	})
}

func TestSafeUnmarshalJSON(t *testing.T) {
	type Config struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	t.Run("ValidUnmarshal", func(t *testing.T) {
		raw := []byte(`{"name":"kelvin","count":42}`)
		var cfg Config
		if err := parserguard.SafeUnmarshalJSON(raw, &cfg); err != nil {
			t.Fatalf("unexpected unmarshal error: %v", err)
		}
		if cfg.Name != "kelvin" || cfg.Count != 42 {
			t.Fatalf("unexpected unmarshaled struct: %+v", cfg)
		}
	})

	t.Run("RejectsUnknownFieldsFailClosed", func(t *testing.T) {
		raw := []byte(`{"name":"kelvin","count":42,"unexpected_field":"rogue"}`)
		var cfg Config
		if err := parserguard.SafeUnmarshalJSON(raw, &cfg); err == nil {
			t.Fatalf("expected error on unknown field under strict unmarshaling")
		}
	})
}

func TestSanitizeFileName(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		shouldErr bool
		expected  string
	}{
		{"SafeSimple", "report.json", false, "report.json"},
		{"RelativeSafePath", "outputs/sub/findings.jsonl", false, "findings.jsonl"},
		{"PathTraversalUnix", "../../etc/passwd", true, ""},
		{"PathTraversalWindows", "..\\..\\windows\\system32\\cmd.exe", true, ""},
		{"AbsoluteUnix", "/var/log/secret.log", true, ""},
		{"AbsoluteWindows", "C:\\Users\\admin\\secret.txt", true, ""},
		{"NullByteInjection", "report\x00.json", true, ""},
		{"Empty", "", true, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := parserguard.SanitizeFileName(tc.input)
			if tc.shouldErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got result %q", tc.input, res)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for input %q: %v", tc.input, err)
				}
				if res != tc.expected {
					t.Fatalf("expected %q, got %q", tc.expected, res)
				}
			}
		})
	}
}

func TestScanBoundedLines(t *testing.T) {
	t.Run("NormalLines", func(t *testing.T) {
		input := "line1\nline2\r\nline3\n"
		var lines []string
		err := parserguard.ScanBoundedLines(strings.NewReader(input), 1024, func(line []byte) error {
			lines = append(lines, string(line))
			return nil
		})
		if err != nil {
			t.Fatalf("unexpected scan error: %v", err)
		}
		if len(lines) != 3 || lines[0] != "line1" || lines[1] != "line2" || lines[2] != "line3" {
			t.Fatalf("unexpected scanned lines: %v", lines)
		}
	})

	t.Run("RejectsOversizedLine", func(t *testing.T) {
		oversized := bytes.Repeat([]byte("A"), 2048)
		input := bytes.Join([][]byte{[]byte("short"), oversized, []byte("short2")}, []byte("\n"))

		err := parserguard.ScanBoundedLines(bytes.NewReader(input), 1024, func(line []byte) error {
			return nil
		})
		if !errors.Is(err, parserguard.ErrLineOversized) {
			t.Fatalf("expected ErrLineOversized, got: %v", err)
		}
	})
}

func TestParserGuard_PanicRecovery(t *testing.T) {
	t.Run("RecoversFromPanicInScanBoundedLinesCallback", func(t *testing.T) {
		input := "line1\nline2\n"
		err := parserguard.ScanBoundedLines(strings.NewReader(input), 1024, func(line []byte) error {
			if string(line) == "line2" {
				panic("simulated fatal parser callback panic")
			}
			return nil
		})
		if err == nil {
			t.Fatal("expected error after callback panic, got nil")
		}
		if !errors.Is(err, parserguard.ErrPanicRecovered) {
			t.Fatalf("expected ErrPanicRecovered, got: %v", err)
		}
		if !strings.Contains(err.Error(), "simulated fatal parser callback panic") {
			t.Fatalf("expected panic message in error string, got: %v", err)
		}
	})
}

func TestParserGuard_OversizedPayloadRejection(t *testing.T) {
	// Exceeds 50MB
	oversizedLen := parserguard.MaxPayloadBytes + 1
	// Using a custom reader or slice with length
	oversized := make([]byte, parserguard.MaxPayloadBytes+10)
	err := parserguard.ValidatePayload(oversized)
	if !errors.Is(err, parserguard.ErrPayloadOversized) {
		t.Fatalf("expected ErrPayloadOversized for %d bytes, got: %v", oversizedLen, err)
	}
}

