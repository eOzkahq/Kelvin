package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMain_WorkerConfigErrorOutputsToStderr(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestMain_WorkerConfigErrorOutputsToStderr")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"KELVIN_ENV=invalid-tier",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected main() to exit with non-zero exit code on invalid staging config")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got: %T", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}

	out := stderr.String()
	if !strings.Contains(out, "worker startup configuration error:") {
		t.Errorf("expected stderr to contain 'worker startup configuration error:', got: %q", out)
	}
}
