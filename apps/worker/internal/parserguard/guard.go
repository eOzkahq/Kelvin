// Package parserguard implements defensive parsing guards against untrusted,
// oversized, or adversarially crafted scanner output payloads.
package parserguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	// MaxPayloadBytes enforces an absolute 50MB ceiling on raw input streams.
	MaxPayloadBytes = 50 * 1024 * 1024

	// MaxNestingDepth limits recursive JSON object/array nesting to prevent stack exhaustion.
	MaxNestingDepth = 32

	// MaxLineBytes enforces a 5MB per-line cap for streaming JSONL parsers.
	MaxLineBytes = 5 * 1024 * 1024

	// MaxSafeStringLength limits individual string fields to prevent memory bloat.
	MaxSafeStringLength = 1024 * 1024
)

var (
	ErrPayloadOversized     = errors.New("parserguard: raw payload exceeds maximum allowed size (50MB)")
	ErrPayloadEmpty         = errors.New("parserguard: raw payload is empty")
	ErrNestingDepthExceeded = errors.New("parserguard: JSON nesting depth exceeds safety limit (max 32)")
	ErrInvalidUTF8          = errors.New("parserguard: payload contains invalid UTF-8 encoding")
	ErrContainsNullBytes    = errors.New("parserguard: payload contains forbidden NUL bytes")
	ErrPathTraversal        = errors.New("parserguard: filename contains unsafe path traversal characters")
	ErrLineOversized        = errors.New("parserguard: streaming line exceeds 5MB size limit")
)

// ValidatePayload verifies size, UTF-8 validity, and absence of NUL bytes.
func ValidatePayload(raw []byte) error {
	if len(raw) == 0 {
		return ErrPayloadEmpty
	}
	if len(raw) > MaxPayloadBytes {
		return fmt.Errorf("%w: got %d bytes", ErrPayloadOversized, len(raw))
	}
	if !utf8.Valid(raw) {
		return ErrInvalidUTF8
	}
	if bytes.IndexByte(raw, 0) != -1 {
		return ErrContainsNullBytes
	}
	return nil
}

// CheckJSONNestingDepth verifies that JSON object/array nesting does not exceed MaxNestingDepth.
func CheckJSONNestingDepth(raw []byte, maxDepth int) error {
	if maxDepth <= 0 {
		maxDepth = MaxNestingDepth
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	depth := 0

	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("parserguard: invalid JSON syntax: %w", err)
		}

		delim, ok := tok.(json.Delim)
		if !ok {
			continue
		}

		switch delim {
		case '{', '[':
			depth++
			if depth > maxDepth {
				return fmt.Errorf("%w: depth %d > %d", ErrNestingDepthExceeded, depth, maxDepth)
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return errors.New("parserguard: unbalanced closing delimiter in JSON")
			}
		}
	}

	if depth != 0 {
		return errors.New("parserguard: incomplete JSON structure (unclosed delimiters)")
	}

	return nil
}

// SafeUnmarshalJSON guards against oversized payloads, invalid UTF-8, and deep nesting
// before deserializing into the target strongly-typed structure.
func SafeUnmarshalJSON(raw []byte, target any) error {
	if err := ValidatePayload(raw); err != nil {
		return err
	}
	if err := CheckJSONNestingDepth(raw, MaxNestingDepth); err != nil {
		return err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields() // Default fail-closed for strictly modeled schemas
	return dec.Decode(target)
}

// SafeUnmarshalLooseJSON unmarshals with nesting and size checks while allowing extra fields.
func SafeUnmarshalLooseJSON(raw []byte, target any) error {
	if err := ValidatePayload(raw); err != nil {
		return err
	}
	if err := CheckJSONNestingDepth(raw, MaxNestingDepth); err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

// SanitizeFileName cleanses and neutralizes scanner-provided file references,
// preventing path traversal, drive letter rootings, and special character injection.
func SanitizeFileName(rawName string) (string, error) {
	clean := strings.TrimSpace(rawName)
	if clean == "" {
		return "", errors.New("parserguard: filename is empty")
	}

	if strings.ContainsAny(clean, "\x00\r\n\t") {
		return "", fmt.Errorf("%w: contains control characters", ErrPathTraversal)
	}

	// Reject absolute or UNC paths
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "/") || strings.HasPrefix(clean, "\\") || strings.Contains(clean, ":") {
		return "", fmt.Errorf("%w: absolute or drive-rooted paths are forbidden", ErrPathTraversal)
	}

	cleanedPath := filepath.Clean(clean)
	if strings.HasPrefix(cleanedPath, "..") || cleanedPath == "." {
		return "", fmt.Errorf("%w: path escapes target boundary", ErrPathTraversal)
	}

	// Extract only the base name
	base := filepath.Base(cleanedPath)
	if base == "." || base == "/" || base == "\\" {
		return "", fmt.Errorf("%w: invalid base filename", ErrPathTraversal)
	}

	return base, nil
}

// ScanBoundedLines streams and validates lines from reader, ensuring no single line exceeds MaxLineBytes.
func ScanBoundedLines(reader io.Reader, maxLineBytes int, fn func(line []byte) error) error {
	if maxLineBytes <= 0 {
		maxLineBytes = MaxLineBytes
	}

	var buf bytes.Buffer
	chunk := make([]byte, 32*1024)

	for {
		n, err := reader.Read(chunk)
		if n > 0 {
			for i := 0; i < n; i++ {
				b := chunk[i]
				if b == '\n' {
					line := bytes.TrimRight(buf.Bytes(), "\r")
					if len(line) > 0 {
						if err := fn(line); err != nil {
							return err
						}
					}
					buf.Reset()
				} else {
					if buf.Len() >= maxLineBytes {
						return fmt.Errorf("%w: line exceeded %d bytes", ErrLineOversized, maxLineBytes)
					}
					buf.WriteByte(b)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				// Process trailing line if present
				line := bytes.TrimRight(buf.Bytes(), "\r")
				if len(line) > 0 {
					return fn(line)
				}
				return nil
			}
			return err
		}
	}
}
