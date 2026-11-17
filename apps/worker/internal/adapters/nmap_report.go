package adapters

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kelvin/kelvin/apps/worker/internal/parserguard"
)

const (
	maxNmapReportBytes = 10 * 1024 * 1024 // 10MB
	maxNmapFindings    = 2000
)

// NmapXMLRun represents the root of an Nmap XML execution report.
type NmapXMLRun struct {
	XMLName  xml.Name      `xml:"nmaprun"`
	Scanner  string        `xml:"scanner,attr"`
	Args     string        `xml:"args,attr"`
	Start    string        `xml:"start,attr"`
	Version  string        `xml:"version,attr"`
	Hosts    []NmapXMLHost `xml:"host"`
	RunStats NmapXMLStats  `xml:"runstats"`
}

type NmapXMLHost struct {
	StartTime string            `xml:"starttime,attr"`
	EndTime   string            `xml:"endtime,attr"`
	Status    NmapXMLStatus     `xml:"status"`
	Addresses []NmapXMLAddress  `xml:"address"`
	Hostnames []NmapXMLHostname `xml:"hostnames>hostname"`
	Ports     []NmapXMLPort     `xml:"ports>port"`
}

type NmapXMLStatus struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapXMLAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type NmapXMLHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type NmapXMLPort struct {
	Protocol string         `xml:"protocol,attr"`
	PortID   int            `xml:"portid,attr"`
	State    NmapXMLState   `xml:"state"`
	Service  NmapXMLService `xml:"service"`
	Scripts  []NmapXMLScript`xml:"script"`
}

type NmapXMLState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type NmapXMLService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Method    string `xml:"method,attr"`
	Conf      int    `xml:"conf,attr"`
}

type NmapXMLScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type NmapXMLStats struct {
	Finished NmapXMLFinished `xml:"finished"`
	Hosts    NmapXMLHosts    `xml:"hosts"`
}

type NmapXMLFinished struct {
	Time    string `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Summary string `xml:"summary,attr"`
	Exit    string `xml:"exit,attr"`
}

type NmapXMLHosts struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// NormalizeNmapXMLReport parses an Nmap XML output string/file into Kelvin canonical findings.
// Target asset identity is derived strictly from the verified Task, preventing spoofing via scan output.
func NormalizeNmapXMLReport(task Task, raw []byte, scannerVersion string, started, completed time.Time) (Result, error) {
	if err := ValidateTask(task); err != nil {
		return Result{}, err
	}
	if task.Scanner != ScannerNmap || scannerVersion == "" || (!started.IsZero() && completed.Before(started)) {
		return Result{}, fmt.Errorf("adapters: invalid Nmap report context")
	}
	if len(raw) == 0 || len(raw) > maxNmapReportBytes {
		return Result{}, fmt.Errorf("adapters: Nmap report is empty or exceeds %d bytes", maxNmapReportBytes)
	}

	if err := parserguard.ValidatePayload(raw); err != nil {
		return Result{}, fmt.Errorf("%w: invalid Nmap XML report payload: %w", ErrMalformedOutput, err)
	}

	decoder := xml.NewDecoder(bytes.NewReader(raw))
	// Harden decoder against external entity expansions
	decoder.Entity = map[string]string{}

	var report NmapXMLRun
	if err := decoder.Decode(&report); err != nil {
		return Result{}, fmt.Errorf("%w: decode Nmap XML report: %v", ErrMalformedOutput, err)
	}

	if report.Scanner != "" && report.Scanner != "nmap" {
		return Result{}, fmt.Errorf("%w: invalid scanner name in XML: %s", ErrMalformedOutput, report.Scanner)
	}

	if started.IsZero() {
		started = time.Now().UTC()
	}
	if completed.IsZero() {
		completed = started
	}

	// Resolve canonical asset name from task.Target
	asset := task.Target
	if u, err := url.Parse(task.Target); err == nil && u.Hostname() != "" {
		asset = u.Hostname()
	}

	findings := make([]json.RawMessage, 0)
	runID := uuid.NewString()

	for _, host := range report.Hosts {
		if host.Status.State != "up" && len(report.Hosts) > 1 {
			continue
		}

		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}

			if len(findings) >= maxNmapFindings {
				break
			}

			// 1. Check NSE scripts for security weaknesses
			for _, script := range port.Scripts {
				scriptFinding, err := parseNmapScriptFinding(task, script, port, asset, scannerVersion, runID, started)
				if err == nil && len(scriptFinding) > 0 {
					findings = append(findings, scriptFinding)
				}
			}

			// 2. Open service discovery finding
			portFinding, err := parseNmapOpenPortFinding(task, port, asset, scannerVersion, runID, started)
			if err == nil && len(portFinding) > 0 {
				findings = append(findings, portFinding)
			}
		}
	}

	cmdArgsJSON, _ := json.Marshal(report.Args)
	result := Result{
		SchemaVersion: OutputEnvelopeVersion,
		Metadata: OutputMetadata{
			AssessmentID:   task.AssessmentID,
			ScannerID:      ScannerNmap,
			ScannerVersion: scannerVersion,
			AdapterVersion: "1.0.0",
			RunID:          runID,
			StartedAt:      started,
			CompletedAt:    completed,
			CorrelationID:  task.CorrelationID,
		},
		Status:        StatusCompleted,
		ExitCode:      intPointer(0),
		DurationMS:    completed.Sub(started).Milliseconds(),
		Findings:      findings,
		Diagnostics:   []ExecutionDiagnostic{},
		RawArtifacts:  RawArtifactReferences{},
		ScannerMetadata: map[string]json.RawMessage{
			"nmap.parser_version": json.RawMessage(`"1.0.0"`),
			"nmap.command_args":   cmdArgsJSON,
		},
	}

	if err := result.Validate(); err != nil {
		return Result{}, fmt.Errorf("%w: normalized Nmap output is invalid: %v", ErrMalformedOutput, err)
	}

	return result, nil
}

func parseNmapScriptFinding(task Task, script NmapXMLScript, port NmapXMLPort, asset, scannerVersion, runID string, discovered time.Time) (json.RawMessage, error) {
	scriptID := strings.TrimSpace(script.ID)
	output := strings.TrimSpace(script.Output)
	if scriptID == "" || output == "" {
		return nil, nil
	}

	title := fmt.Sprintf("Nmap Script Output: %s on %d/%s", scriptID, port.PortID, port.Protocol)
	severity := "INFORMATIONAL"
	confidence := 0.8
	rule := "nse-script-default-informational"
	cweID := ""
	tags := []string{"nmap", "nse", scriptID}

	// Rule: TLS/SSL CBC Cipher Suites Detection
	if scriptID == "ssl-enum-ciphers" && (strings.Contains(output, "CBC") || strings.Contains(output, "weak")) {
		title = "TLS/SSL Server Supports CBC Cipher Suites"
		severity = "MEDIUM"
		confidence = 0.9
		rule = "tls-cbc-default-medium"
		cweID = "CWE-327"
		tags = []string{"tls", "ciphers", "misconfiguration"}
	}

	vulnerability := map[string]string{}
	if cweID != "" {
		vulnerability["cwe_id"] = cweID
	}

	findingMap := map[string]any{
		"schema_version": "1.0",
		"title":          title,
		"severity":       severity,
		"confidence":     confidence,
		"target": map[string]any{
			"asset": asset,
		},
		"vulnerability":  vulnerability,
		"description":    fmt.Sprintf("Nmap script %s identified potential security or service details on %s:%d (%s).", scriptID, asset, port.PortID, port.Protocol),
		"evidence": []map[string]any{
			{
				"type":             "LOG",
				"content_type":     "text/plain",
				"content_redacted": sanitizeNmapEvidence(output),
				"size_bytes":       len(output),
				"redacted_fields":  []string{},
			},
		},
		"scanner": map[string]any{
			"name":            ScannerNmap,
			"adapter_version": "1.0.0",
			"engine_version":  scannerVersion,
			"run_id":          runID,
		},
		"scanner_meta": map[string]string{
			"nmap.script_id":       scriptID,
			"nmap.port":            strconv.Itoa(port.PortID),
			"nmap.protocol":        port.Protocol,
			"kelvin.severity_rule": rule,
		},
		"tags":          tags,
		"discovered_at": discovered.Format(time.RFC3339),
	}

	if cweID != "" {
		findingMap["remediation"] = map[string]any{
			"summary":    "Disable weak cipher suites; prefer AEAD suites (AES-GCM, ChaCha20-Poly1305).",
			"references": []string{"https://ssl-config.mozilla.org/"},
		}
	}

	return json.Marshal(findingMap)
}

func parseNmapOpenPortFinding(task Task, port NmapXMLPort, asset, scannerVersion, runID string, discovered time.Time) (json.RawMessage, error) {
	serviceName := port.Service.Name
	if serviceName == "" {
		serviceName = "unknown"
	}

	title := fmt.Sprintf("Discovered Open Port: %s/%d (%s)", port.Protocol, port.PortID, serviceName)
	severity := "INFORMATIONAL"
	confidence := 0.9
	rule := "open-service-default-informational"
	cweID := ""
	tags := []string{"discovery", "port_scan", "network"}

	// Heuristics for plaintext protocols
	switch {
	case serviceName == "telnet" || port.PortID == 23:
		title = fmt.Sprintf("Unencrypted Telnet Service Detected on Port %d/%s", port.PortID, port.Protocol)
		severity = "HIGH"
		rule = "plaintext-protocol-high"
		cweID = "CWE-319"
		tags = append(tags, "plaintext", "insecure-transport")
	case serviceName == "ftp" || port.PortID == 21:
		title = fmt.Sprintf("Unencrypted FTP Service Detected on Port %d/%s", port.PortID, port.Protocol)
		severity = "MEDIUM"
		rule = "plaintext-protocol-medium"
		cweID = "CWE-319"
		tags = append(tags, "plaintext", "insecure-transport")
	}

	desc := fmt.Sprintf("Nmap detected open %s port %d on %s running service %s.", port.Protocol, port.PortID, asset, serviceName)
	if port.Service.Product != "" {
		desc += fmt.Sprintf(" Product: %s", port.Service.Product)
		if port.Service.Version != "" {
			desc += fmt.Sprintf(" Version: %s", port.Service.Version)
		}
	}

	evidenceText := fmt.Sprintf("Port %d/%s is open (reason: %s). Service: %s", port.PortID, port.Protocol, port.State.Reason, serviceName)
	vulnerability := map[string]string{}
	if cweID != "" {
		vulnerability["cwe_id"] = cweID
	}

	findingMap := map[string]any{
		"schema_version": "1.0",
		"title":          title,
		"severity":       severity,
		"confidence":     confidence,
		"target": map[string]any{
			"asset": asset,
		},
		"vulnerability": vulnerability,
		"description":   desc,
		"evidence": []map[string]any{
			{
				"type":             "LOG",
				"content_type":     "text/plain",
				"content_redacted": evidenceText,
				"size_bytes":       len(evidenceText),
				"redacted_fields":  []string{},
			},
		},
		"scanner": map[string]any{
			"name":            ScannerNmap,
			"adapter_version": "1.0.0",
			"engine_version":  scannerVersion,
			"run_id":          runID,
		},
		"scanner_meta": map[string]string{
			"nmap.port":            strconv.Itoa(port.PortID),
			"nmap.protocol":        port.Protocol,
			"nmap.service":         serviceName,
			"kelvin.severity_rule": rule,
		},
		"tags":          tags,
		"discovered_at": discovered.Format(time.RFC3339),
	}

	if cweID != "" {
		findingMap["remediation"] = map[string]any{
			"summary":    "Disable unencrypted plaintext protocols or upgrade to encrypted alternatives (e.g. SSH, SFTP).",
			"references": []string{"https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"},
		}
	}

	return json.Marshal(findingMap)
}

func sanitizeNmapEvidence(text string) string {
	const maxLen = 4096
	sanitized := strings.ToValidUTF8(text, "")
	if len(sanitized) > maxLen {
		return sanitized[:maxLen] + " [TRUNCATED]"
	}
	return sanitized
}
