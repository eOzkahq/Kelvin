package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	var (
		sbomPath    string
		registryPath string
		scannerName string
		auditDateStr string
		outputPath  string
	)

	flag.StringVar(&sbomPath, "sbom", "", "Path to raw CycloneDX SBOM JSON file (optional)")
	flag.StringVar(&registryPath, "registry", "", "Path to canonical waiver registry YAML file (required)")
	flag.StringVar(&scannerName, "scanner", "scanner", "Scanner name (e.g. nuclei or zap)")
	flag.StringVar(&auditDateStr, "audit-date", "", "Audit date formatted as YYYY-MM-DD (defaults to today)")
	flag.StringVar(&outputPath, "output", "", "Optional path to write JSON reconciliation report")
	flag.Parse()

	if registryPath == "" {
		fmt.Fprintln(os.Stderr, "ERROR: --registry <path> is required")
		flag.Usage()
		os.Exit(2)
	}

	auditDate := time.Now().UTC()
	if auditDateStr != "" {
		parsed, err := time.Parse(DateFormat, auditDateStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Invalid --audit-date %q. Must be YYYY-MM-DD: %v\n", auditDateStr, err)
			os.Exit(2)
		}
		auditDate = parsed
	}

	engine := NewEngine(auditDate)

	registry, err := engine.LoadWaiverRegistry(registryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to load waiver registry: %v\n", err)
		os.Exit(2)
	}

	var sbom *CycloneDXSBOM
	if sbomPath != "" {
		loadedSBOM, err := engine.LoadSBOM(sbomPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to load SBOM: %v\n", err)
			os.Exit(2)
		}
		sbom = loadedSBOM
	} else {
		sbom = &CycloneDXSBOM{}
	}

	report, err := engine.Reconcile(scannerName, sbom, registry)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Reconciliation failed: %v\n", err)
		os.Exit(2)
	}

	// Output summary to stdout
	fmt.Println("==============================================================================")
	fmt.Printf("Kelvin Vulnerability & Waiver Reconciliation: %s\n", scannerName)
	fmt.Printf("Audit Date: %s | Policy: ADR-0008 (Fail-Closed)\n", report.AuditDate)
	fmt.Println("==============================================================================")
	fmt.Printf("  Total Raw Findings:           %d\n", report.TotalRawFindings)
	fmt.Printf("  Total Waivers Registered:     %d\n", report.TotalRegisteredWaivers)
	fmt.Printf("  [+] Fixed (Remediated):       %d\n", report.Summary.Fixed)
	fmt.Printf("  [=] Approved (Suppressing):   %d\n", report.Summary.Approved)
	fmt.Printf("  [?] Pending Review (Gated):   %d\n", report.Summary.Pending)
	fmt.Printf("  [!] Expired Waivers (Gated):  %d\n", report.Summary.Expired)
	fmt.Printf("  [X] Unhandled CVEs (Gated):   %d\n", report.Summary.Unhandled)
	fmt.Println("------------------------------------------------------------------------------")
	fmt.Printf("RECONCILIATION VERDICT: [%s]\n", report.Verdict)
	fmt.Println("==============================================================================")

	if outputPath != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to marshal report JSON: %v\n", err)
			os.Exit(2)
		}
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Failed to write report output to %s: %v\n", outputPath, err)
			os.Exit(2)
		}
		fmt.Printf("Machine-readable report written to: %s\n", outputPath)
	}

	if report.Verdict == VerdictPass {
		os.Exit(0)
	} else {
		os.Exit(1)
	}
}
