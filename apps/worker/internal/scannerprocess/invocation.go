// Package scannerprocess builds the only permitted external scanner
// invocations from validated task and scanner configuration data.
package scannerprocess

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/kelvin/kelvin/apps/worker/internal/adapters"
	"github.com/kelvin/kelvin/apps/worker/internal/sandbox"
)

const nucleiTemplatePath = "/opt/kelvin/templates/kelvin.safe.web.v1"

// Build creates a scanner-specific argv using fixed executable paths and
// options derived from the versioned, allow-listed scanner configuration.
func Build(task adapters.Task) (sandbox.ProcessInvocation, error) {
	if err := adapters.ValidateTask(task); err != nil {
		return sandbox.ProcessInvocation{}, err
	}
	target, err := validateTarget(task.Target)
	if err != nil {
		return sandbox.ProcessInvocation{}, err
	}
	config, err := scannerConfig(task)
	if err != nil {
		return sandbox.ProcessInvocation{}, err
	}
	if err := config.Validate(); err != nil {
		return sandbox.ProcessInvocation{}, err
	}

	switch task.Scanner {
	case adapters.ScannerZAPBaseline:
		minutes := int(math.Ceil(float64(config.MaxDurationSeconds) / 60.0))
		zapOptions := fmt.Sprintf("-config spider.maxDepth=%d -config spider.maxChildren=%d -config spider.threadCount=%d", config.ZAP.MaxDepth, config.ZAP.MaxURLs, config.MaxConcurrency)
		return sandbox.ProcessInvocation{Executable: "/zap/zap-baseline.py", Args: []string{
			"-t", target, "-m", strconv.Itoa(minutes), "-T", strconv.Itoa(minutes),
			"-I", "-J", "/tmp/kelvin-zap-report.json", "-z", zapOptions,
		}}, nil
	case adapters.ScannerNuclei:
		return sandbox.ProcessInvocation{Executable: "/nuclei", Args: []string{
			"-duc", "-u", target, "-t", nucleiTemplatePath,
			"-severity", strings.Join(config.Nuclei.SeverityAllowlist, ","),
			"-rl", strconv.Itoa(config.RequestsPerSecond), "-c", strconv.Itoa(config.MaxConcurrency),
			"-timeout", strconv.Itoa(config.RequestTimeoutSeconds), "-jsonl", "-silent", "-no-color",
		}}, nil
	default:
		return sandbox.ProcessInvocation{}, fmt.Errorf("scanner process: %q has no external executable allow-list", task.Scanner)
	}
}

func scannerConfig(task adapters.Task) (adapters.ScannerConfigV1, error) {
	raw := strings.TrimSpace(string(task.Payload))
	if raw == "" || raw == "null" {
		return adapters.DefaultScannerConfig(task.Scanner)
	}
	config, err := adapters.DecodeScannerConfig([]byte(raw))
	if err != nil {
		return adapters.ScannerConfigV1{}, err
	}
	if config.ScannerID != task.Scanner {
		return adapters.ScannerConfigV1{}, fmt.Errorf("scanner process: config scanner_id does not match task")
	}
	return config, nil
}

func validateTarget(raw string) (string, error) {
	if len(raw) > 2048 || strings.ContainsAny(raw, "\x00\r\n\t ") || strings.HasPrefix(raw, "-") {
		return "", fmt.Errorf("scanner process: target contains invalid characters")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return "", fmt.Errorf("scanner process: target must be an absolute HTTP(S) URL without userinfo or fragment")
	}
	return u.String(), nil
}
