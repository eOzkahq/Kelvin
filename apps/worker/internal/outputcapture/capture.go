// Package outputcapture implements bounded, memory-safe capture of scanner
// standard output and standard error streams.
package outputcapture

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"unicode/utf8"
)

const (
	// DefaultMaxCaptureBytes is the default maximum capture limit per stream (16MB).
	DefaultMaxCaptureBytes = 16 * 1024 * 1024

	// AbsoluteMaxCaptureBytes is the upper bound ceiling permitted (50MB).
	AbsoluteMaxCaptureBytes = 50 * 1024 * 1024

	// TruncationMarker is appended to captured output when the stream exceeds the limit.
	TruncationMarker = "\n... [OUTPUT TRUNCATED: maximum capture buffer limit reached]\n"
)

var (
	// ErrLimitExceeded is returned when non-truncating capture modes encounter overflow.
	ErrLimitExceeded = errors.New("output capture: stream exceeded maximum allowed size")
)

// Config configures stream capture behavior.
type Config struct {
	MaxBytes       int
	SanitizeUTF8   bool
	PreserveBinary bool
}

// DefaultConfig returns recommended production defaults.
func DefaultConfig() Config {
	return Config{
		MaxBytes:     DefaultMaxCaptureBytes,
		SanitizeUTF8: true,
	}
}

// BoundedWriter is an io.Writer that captures up to MaxBytes of output in memory.
// Once MaxBytes is reached, subsequent writes are safely discarded to protect
// worker memory, and the buffer is marked as truncated.
type BoundedWriter struct {
	mu           sync.Mutex
	buf          bytes.Buffer
	maxBytes     int
	totalBytes   int64
	truncated    bool
	sanitizeUTF8 bool
}

// NewBoundedWriter creates a thread-safe writer with the specified maximum byte limit.
func NewBoundedWriter(maxBytes int) *BoundedWriter {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxCaptureBytes
	}
	if maxBytes > AbsoluteMaxCaptureBytes {
		maxBytes = AbsoluteMaxCaptureBytes
	}
	return &BoundedWriter{
		maxBytes:     maxBytes,
		sanitizeUTF8: true,
	}
}

// Write appends incoming bytes up to the configured limit, discarding overflow.
func (w *BoundedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	n := len(p)
	w.totalBytes += int64(n)

	limit := w.maxBytes - len(TruncationMarker)
	if limit < 0 {
		limit = 0
	}

	remaining := limit - w.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			w.buf.Write(p[:remaining])
			w.truncated = true
		} else {
			w.buf.Write(p)
		}
	} else {
		w.truncated = true
	}

	return n, nil
}

// Bytes returns the captured byte slice.
func (w *BoundedWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()

	raw := w.buf.Bytes()
	if !w.truncated {
		out := make([]byte, len(raw))
		copy(out, raw)
		return out
	}

	out := make([]byte, len(raw)+len(TruncationMarker))
	copy(out, raw)
	copy(out[len(raw):], TruncationMarker)
	return out
}

// String returns the captured output as a string, sanitized to valid UTF-8 if configured.
func (w *BoundedWriter) String() string {
	raw := w.Bytes()
	if len(raw) == 0 {
		return ""
	}
	if w.sanitizeUTF8 && !utf8.Valid(raw) {
		return SanitizeValidUTF8(raw)
	}
	return string(raw)
}

// TotalBytes returns the total number of bytes read across all Write calls.
func (w *BoundedWriter) TotalBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.totalBytes
}

// CapturedBytes returns the number of retained bytes in memory.
func (w *BoundedWriter) CapturedBytes() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Len()
}

// Truncated returns whether incoming output exceeded the configured capture limit.
func (w *BoundedWriter) Truncated() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.truncated
}

// Reset clears the buffer and resets counters.
func (w *BoundedWriter) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Reset()
	w.totalBytes = 0
	w.truncated = false
}

// DualStreamCapture coordinates independent capture of stdout and stderr streams.
type DualStreamCapture struct {
	Stdout *BoundedWriter
	Stderr *BoundedWriter
}

// NewDualStreamCapture initializes separate bounded writers for stdout and stderr.
func NewDualStreamCapture(maxBytes int) *DualStreamCapture {
	return &DualStreamCapture{
		Stdout: NewBoundedWriter(maxBytes),
		Stderr: NewBoundedWriter(maxBytes),
	}
}

// StreamResult summarizes the captured output from dual streams.
type StreamResult struct {
	Stdout          string
	Stderr          string
	StdoutBytes     int64
	StderrBytes     int64
	StdoutTruncated bool
	StderrTruncated bool
}

// Result compiles captured output and truncation metadata.
func (d *DualStreamCapture) Result() StreamResult {
	return StreamResult{
		Stdout:          d.Stdout.String(),
		Stderr:          d.Stderr.String(),
		StdoutBytes:     d.Stdout.TotalBytes(),
		StderrBytes:     d.Stderr.TotalBytes(),
		StdoutTruncated: d.Stdout.Truncated(),
		StderrTruncated: d.Stderr.Truncated(),
	}
}

// CopyBounded streams from src into dst while respecting context cancellation.
func CopyBounded(ctx context.Context, dst *BoundedWriter, src io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := src.Read(buf)
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// SanitizeValidUTF8 converts raw byte sequences into valid UTF-8, replacing
// invalid UTF-8 byte sequences with Unicode replacement characters (\uFFFD).
func SanitizeValidUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var buf bytes.Buffer
	buf.Grow(len(b))
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			buf.WriteRune('\uFFFD')
		} else {
			buf.WriteRune(r)
		}
		b = b[size:]
	}
	return buf.String()
}
