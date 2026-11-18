// Package scannerprocess builds the only permitted external scanner
// invocations from validated task and scanner configuration data.
package scannerprocess

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

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
		minutes := config.MaxDurationSeconds / 60
		executable := "/zap/zap-baseline.py"
		if config.ExecutionMode == "ACTIVE" || (config.ZAP != nil && config.ZAP.ActiveScan) {
			profile, err := adapters.GetAssessmentProfile(task.ProfileID)
			if err != nil || profile.TrafficLevel != "active" || !profile.AdminSignoffRequired {
				return sandbox.ProcessInvocation{}, fmt.Errorf("scanner process: ZAP active scan requires authorized active assessment profile (got %q)", task.ProfileID)
			}
			executable = "/zap/zap-full-scan.py"
		}
		zapOptions := fmt.Sprintf("-config spider.maxDepth=%d -config spider.maxChildren=%d -config spider.threadCount=1 -config network.connection.timeoutInSecs=%d", config.ZAP.MaxDepth, config.ZAP.MaxChildren, config.RequestTimeoutSeconds)
		return sandbox.ProcessInvocation{Executable: executable, Args: []string{
			"-t", target, "-m", strconv.Itoa(minutes), "-T", strconv.Itoa(minutes),
			"-I", "-J", "/tmp/kelvin-zap-report.json", "-z", zapOptions,
		}}, nil
	case adapters.ScannerNuclei:
		return sandbox.ProcessInvocation{Executable: "/nuclei", Args: adapters.BuildNucleiArgs(task)}, nil
	default:
		return sandbox.ProcessInvocation{}, fmt.Errorf("scanner process: %q has no external executable allow-list", task.Scanner)
	}
}

// EffectiveDeadline applies scanner-configured duration as an additional
// ceiling. The caller still supplies the absolute job/profile deadline.
func EffectiveDeadline(task adapters.Task) (time.Duration, error) {
	if err := adapters.ValidateTask(task); err != nil {
		return 0, err
	}
	config, err := scannerConfig(task)
	if err != nil {
		return 0, err
	}
	if err := config.Validate(); err != nil {
		return 0, err
	}
	configured := time.Duration(config.MaxDurationSeconds) * time.Second
	if task.HardDeadline < configured {
		return task.HardDeadline, nil
	}
	return configured, nil
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
