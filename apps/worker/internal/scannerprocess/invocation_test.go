package scannerprocess

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
)

func taskFor(scanner, target string) adapters.Task {
	return adapters.Task{
		JobID: "11111111-1111-1111-1111-111111111111", AssessmentID: "22222222-2222-2222-2222-222222222222",
		TenantID: "33333333-3333-3333-3333-333333333333", Scanner: scanner, Target: target,
		ProfileID: "kelvin.profile.standard.v1", HardDeadline: 10 * time.Minute,
	}
}

func TestBuildNucleiUsesPinnedSafeOptionsAndArgv(t *testing.T) {
	task := taskFor(adapters.ScannerNuclei, "https://example.com/path")
	invocation, err := Build(task)
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Executable != "/nuclei" {
		t.Fatalf("executable = %q", invocation.Executable)
	}
	joined := strings.Join(invocation.Args, "\x00")
	for _, want := range []string{"-duc", "-u\x00https://example.com/path", "-t\x00" + nucleiTemplatePath, "-severity\x00info,low,medium", "-rl\x002"} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv %q missing %q", joined, want)
		}
	}
	if strings.Contains(joined, "$(") || strings.Contains(joined, "-headless") || strings.Contains(joined, "-unsafe") {
		t.Fatalf("unsafe/unsolicited option present in argv: %q", joined)
	}
}

func TestBuildZAPMapsOnlyBoundedValidatedConfiguration(t *testing.T) {
	task := taskFor(adapters.ScannerZAPBaseline, "https://example.com")
	config, err := adapters.DefaultScannerConfig(task.Scanner)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxDurationSeconds = 120
	config.ZAP.MaxDepth = 2
	config.ZAP.MaxChildren = 8
	task.Payload, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := Build(task)
	if err != nil {
		t.Fatal(err)
	}
	if invocation.Executable != "/zap/zap-baseline.py" {
		t.Fatalf("executable = %q", invocation.Executable)
	}
	want := []string{"-t", "https://example.com", "-m", "2", "-T", "2", "-I", "-J", "/tmp/kelvin-zap-report.json", "-z", "-config spider.maxDepth=2 -config spider.maxChildren=8 -config spider.threadCount=1 -config network.connection.timeoutInSecs=10"}
	if len(invocation.Args) != len(want) {
		t.Fatalf("argv = %#v", invocation.Args)
	}
	for i := range want {
		if invocation.Args[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, invocation.Args[i], want[i])
		}
	}
}

func TestZAPSafetyProfileOmitsActiveScanAndOptionalExecutionModes(t *testing.T) {
	invocation, err := Build(taskFor(adapters.ScannerZAPBaseline, "https://example.com"))
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(invocation.Args, "\x00")
	for _, arg := range invocation.Args {
		switch arg {
		case "-j", "-a", "-c", "-u", "-n", "--hook", "--auto":
			t.Fatalf("ZAP invocation contains prohibited option %q: %#v", arg, invocation.Args)
		}
	}
	if !strings.Contains(joined, "spider.maxDepth=2") || !strings.Contains(joined, "spider.maxChildren=10") || !strings.Contains(joined, "spider.threadCount=1") || !strings.Contains(joined, "network.connection.timeoutInSecs=10") {
		t.Fatalf("safe profile bounds missing: %#v", invocation.Args)
	}
}

func TestEffectiveDeadlineUsesNarrowerScannerOrJobLimit(t *testing.T) {
	task := taskFor(adapters.ScannerZAPBaseline, "https://example.com")
	if got, err := EffectiveDeadline(task); err != nil || got != 10*time.Minute {
		t.Fatalf("default effective deadline=%s err=%v", got, err)
	}
	task.HardDeadline = 4 * time.Minute
	if got, err := EffectiveDeadline(task); err != nil || got != 4*time.Minute {
		t.Fatalf("narrow job deadline=%s err=%v", got, err)
	}
	config, _ := adapters.DefaultScannerConfig(task.Scanner)
	config.MaxDurationSeconds = 120
	task.HardDeadline = 10 * time.Minute
	task.Payload, _ = json.Marshal(config)
	if got, err := EffectiveDeadline(task); err != nil || got != 2*time.Minute {
		t.Fatalf("narrow scanner deadline=%s err=%v", got, err)
	}
}

func TestBuildRejectsUnknownScannerTargetAndUnapprovedConfig(t *testing.T) {
	cases := []struct {
		name string
		task adapters.Task
	}{
		{"unknown scanner", taskFor("unknown", "https://example.com")},
		{"target option injection", taskFor(adapters.ScannerNuclei, "--help")},
		{"target userinfo", taskFor(adapters.ScannerZAPBaseline, "https://user:pass@example.com")},
		{"target fragment", taskFor(adapters.ScannerNuclei, "https://example.com/#fragment")},
	}
	badConfig := taskFor(adapters.ScannerNuclei, "https://example.com")
	badConfig.Payload = []byte(`{"schema_version":"1.0","scanner_id":"nuclei","execution_mode":"PASSIVE","request_timeout_seconds":10,"max_duration_seconds":300,"requests_per_second":2,"max_concurrency":1,"extra_args":["-unsafe"]}`)
	cases = append(cases, struct {
		name string
		task adapters.Task
	}{"arbitrary config argument", badConfig})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Build(tc.task); err == nil {
				t.Fatal("Build accepted invalid invocation input")
			}
		})
	}
}

func TestBuildPreservesMetacharactersAsSingleURLArgument(t *testing.T) {
	target := "https://example.com/path/%24%28touch%20/tmp/pwned%29"
	invocation, err := Build(taskFor(adapters.ScannerNuclei, target))
	if err != nil {
		t.Fatal(err)
	}
	for i, arg := range invocation.Args {
		if arg == "-u" {
			if invocation.Args[i+1] != target {
				t.Fatalf("target was reparsed or changed: %q", invocation.Args[i+1])
			}
			return
		}
	}
	t.Fatal("target argument not found")
}
