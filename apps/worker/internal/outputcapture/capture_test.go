package outputcapture_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/outputcapture"
)

func TestBoundedWriterEmpty(t *testing.T) {
	w := outputcapture.NewBoundedWriter(1024)
	if w.Truncated() {
		t.Fatalf("expected Truncated = false")
	}
	if w.TotalBytes() != 0 {
		t.Fatalf("expected TotalBytes = 0, got %d", w.TotalBytes())
	}
	if w.CapturedBytes() != 0 {
		t.Fatalf("expected CapturedBytes = 0, got %d", w.CapturedBytes())
	}
	if str := w.String(); str != "" {
		t.Fatalf("expected empty string, got %q", str)
	}
	if len(w.Bytes()) != 0 {
		t.Fatalf("expected empty bytes, got %v", w.Bytes())
	}
}

func TestBoundedWriterNormal(t *testing.T) {
	w := outputcapture.NewBoundedWriter(1024)
	input := "scanner started\nchecking target https://example.com\nscan completed successfully\n"

	n, err := w.Write([]byte(input))
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(input) {
		t.Fatalf("expected %d bytes written, got %d", len(input), n)
	}
	if w.Truncated() {
		t.Fatalf("expected Truncated = false")
	}
	if w.TotalBytes() != int64(len(input)) {
		t.Fatalf("expected TotalBytes = %d, got %d", len(input), w.TotalBytes())
	}
	if w.String() != input {
		t.Fatalf("expected %q, got %q", input, w.String())
	}
}

func TestBoundedWriterOversizedTruncation(t *testing.T) {
	limit := 1024
	w := outputcapture.NewBoundedWriter(limit)

	// Write 50KB in chunks into a 1KB buffer
	chunk := bytes.Repeat([]byte("A"), 256)
	var totalWritten int64
	for i := 0; i < 200; i++ {
		n, err := w.Write(chunk)
		if err != nil {
			t.Fatalf("unexpected write error on chunk %d: %v", i, err)
		}
		totalWritten += int64(n)
	}

	if !w.Truncated() {
		t.Fatalf("expected buffer to be marked as truncated")
	}
	if w.TotalBytes() != totalWritten {
		t.Fatalf("expected TotalBytes = %d, got %d", totalWritten, w.TotalBytes())
	}
	if w.CapturedBytes() > limit {
		t.Fatalf("captured bytes (%d) exceeded limit (%d)", w.CapturedBytes(), limit)
	}

	str := w.String()
	if !strings.Contains(str, outputcapture.TruncationMarker) {
		t.Fatalf("expected output to contain TruncationMarker, got: %s", str)
	}
	if !strings.HasPrefix(str, "AAAA") {
		t.Fatalf("expected output to retain initial content")
	}
}

func TestBoundedWriterMalformedUTF8(t *testing.T) {
	w := outputcapture.NewBoundedWriter(1024)

	// Valid prefix + invalid UTF-8 bytes + valid suffix
	malformed := []byte("valid prefix: \xFF\xFE\xFD invalid bytes: \x80\xBF - valid suffix")
	_, err := w.Write(malformed)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}

	sanitized := w.String()
	if strings.Contains(sanitized, "\xFF") || strings.Contains(sanitized, "\xFE") {
		t.Fatalf("expected malformed bytes to be sanitized, got: %q", sanitized)
	}
	if !strings.Contains(sanitized, "valid prefix:") || !strings.Contains(sanitized, "- valid suffix") {
		t.Fatalf("expected valid text to be preserved, got: %q", sanitized)
	}
	if !strings.Contains(sanitized, "\uFFFD") {
		t.Fatalf("expected Unicode replacement characters in place of invalid bytes")
	}
}

func TestDualStreamCaptureSeparation(t *testing.T) {
	dual := outputcapture.NewDualStreamCapture(2048)

	stdoutData := "STDOUT: found 2 open ports [80, 443]\n"
	stderrData := "STDERR: warning: slow server response on target\n"

	_, err1 := dual.Stdout.Write([]byte(stdoutData))
	_, err2 := dual.Stderr.Write([]byte(stderrData))
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected write error: stdout=%v, stderr=%v", err1, err2)
	}

	res := dual.Result()
	if res.Stdout != stdoutData {
		t.Fatalf("expected stdout %q, got %q", stdoutData, res.Stdout)
	}
	if res.Stderr != stderrData {
		t.Fatalf("expected stderr %q, got %q", stderrData, res.Stderr)
	}
	if res.StdoutTruncated || res.StderrTruncated {
		t.Fatalf("expected neither stream to be truncated")
	}
	if res.StdoutBytes != int64(len(stdoutData)) || res.StderrBytes != int64(len(stderrData)) {
		t.Fatalf("unexpected stream byte counts: stdout=%d, stderr=%d", res.StdoutBytes, res.StderrBytes)
	}
}

func TestCopyBoundedWithCancellation(t *testing.T) {
	w := outputcapture.NewBoundedWriter(4096)
	pr, pw := io.Pipe()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- outputcapture.CopyBounded(ctx, w, pr)
	}()

	// Write one chunk
	_, _ = pw.Write([]byte("initial message\n"))

	// Cancel context while pipe writer is still open
	time.Sleep(10 * time.Millisecond)
	cancel()

	// Unblock reader if waiting
	_ = pw.Close()

	err := <-errCh
	if err != nil && !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("expected context canceled or nil, got: %v", err)
	}

	if !strings.Contains(w.String(), "initial message") {
		t.Fatalf("expected initial message to be captured before cancellation")
	}
}

func TestBoundedWriterConcurrentWrites(t *testing.T) {
	w := outputcapture.NewBoundedWriter(64 * 1024)

	var wg sync.WaitGroup
	workers := 8
	iterations := 50
	line := "concurrent log line\n"

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = w.Write([]byte(line))
			}
		}()
	}

	wg.Wait()

	expectedTotal := int64(workers * iterations * len(line))
	if w.TotalBytes() != expectedTotal {
		t.Fatalf("expected TotalBytes = %d, got %d", expectedTotal, w.TotalBytes())
	}
	if w.CapturedBytes() != int(expectedTotal) {
		t.Fatalf("expected CapturedBytes = %d, got %d", expectedTotal, w.CapturedBytes())
	}
}
