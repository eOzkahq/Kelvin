package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Engine performs deterministic vulnerability and waiver reconciliation.
type Engine struct {
	AuditDate time.Time
}

func NewEngine(auditDate time.Time) *Engine {
	return &Engine{AuditDate: auditDate}
}

func (e *Engine) LoadWaiverRegistry(path string) (*WaiverRegistry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read waiver registry file: %w", err)
	}

	var reg WaiverRegistry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("unmarshal waiver registry YAML: %w", err)
	}

	return &reg, nil
}

func (e *Engine) LoadSBOM(path string) (*CycloneDXSBOM, error) {
	if path == "" {
		return &CycloneDXSBOM{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SBOM file: %w", err)
	}

	var sbom CycloneDXSBOM
	if err := json.Unmarshal(data, &sbom); err != nil {
		return nil, fmt.Errorf("unmarshal CycloneDX JSON: %w", err)
	}

	return &sbom, nil
}

func (e *Engine) Reconcile(scannerName string, sbom *CycloneDXSBOM, reg *WaiverRegistry) (*ReconciliationReport, error) {
	report := &ReconciliationReport{
		SchemaVersion:          "1.0.0",
		AuditDate:              e.AuditDate.Format(DateFormat),
		Scanner:                scannerName,
		TotalRawFindings:       len(sbom.Vulnerabilities),
		TotalRegisteredWaivers: len(reg.Waivers),
		Findings:               make([]ReconciledFinding, 0),
	}

	// 1. Build lookup index of registered waivers
	// Key: cve_id -> []WaiverEntry
	waiversByCVE := make(map[string][]WaiverEntry)
	for _, w := range reg.Waivers {
		cve := strings.TrimSpace(w.CVEID)
		waiversByCVE[cve] = append(waiversByCVE[cve], w)
	}

	matchedWaiverPairs := make(map[string]bool) // Key: cve_id + ":" + component

	// 2. Classify every raw SBOM vulnerability finding
	for _, raw := range sbom.Vulnerabilities {
		cve := strings.TrimSpace(raw.ID)
		severity := "UNKNOWN"
		if len(raw.Ratings) > 0 && raw.Ratings[0].Severity != "" {
			severity = strings.ToUpper(raw.Ratings[0].Severity)
		}

		comp := "UNKNOWN"
		if len(raw.Affects) > 0 && raw.Affects[0].Ref != "" {
			comp = raw.Affects[0].Ref
		}

		candidates := waiversByCVE[cve]
		if len(candidates) == 0 {
			// Unhandled finding (no waiver registered at all)
			report.Summary.Unhandled++
			report.Findings = append(report.Findings, ReconciledFinding{
				CVEID:       cve,
				Component:   comp,
				Severity:    severity,
				Disposition: DispositionUnhandled,
				Reason:      "No registered waiver exception exists in registry",
			})
			continue
		}

		// Find best matching waiver by component or take first
		var matched *WaiverEntry
		for i := range candidates {
			w := &candidates[i]
			// Normalize component matching
			if comp == "UNKNOWN" || w.Component == comp || strings.Contains(w.Component, comp) || strings.Contains(comp, w.Component) {
				matched = w
				break
			}
		}
		if matched == nil {
			matched = &candidates[0]
		}

		pairKey := matched.CVEID + ":" + matched.Component
		matchedWaiverPairs[pairKey] = true

		// Check status and expiration
		switch matched.Status {
		case "approved":
			if matched.ExpiryDate == nil || *matched.ExpiryDate == "" {
				report.Summary.Expired++
				report.Findings = append(report.Findings, ReconciledFinding{
					CVEID:       cve,
					Component:   comp,
					Severity:    severity,
					Disposition: DispositionExpired,
					Reason:      "Approved waiver has missing expiry date (fails closed)",
				})
			} else {
				expiry, err := parseDate(*matched.ExpiryDate)
				if err != nil || expiry.Before(e.AuditDate) {
					report.Summary.Expired++
					report.Findings = append(report.Findings, ReconciledFinding{
						CVEID:       cve,
						Component:   comp,
						Severity:    severity,
						Disposition: DispositionExpired,
						Reason:      fmt.Sprintf("Waiver expired on %s", *matched.ExpiryDate),
						ExpiryDate:  *matched.ExpiryDate,
					})
				} else {
					report.Summary.Approved++
					report.Findings = append(report.Findings, ReconciledFinding{
						CVEID:       cve,
						Component:   comp,
						Severity:    severity,
						Disposition: DispositionApproved,
						Reason:      "Active approved maintainer waiver in effect",
						ExpiryDate:  *matched.ExpiryDate,
					})
				}
			}
		case "pending_review":
			report.Summary.Pending++
			report.Findings = append(report.Findings, ReconciledFinding{
				CVEID:       cve,
				Component:   comp,
				Severity:    severity,
				Disposition: DispositionPending,
				Reason:      "Waiver is pending maintainer review (non-suppressing)",
			})
		case "rejected":
			report.Summary.Unhandled++
			report.Findings = append(report.Findings, ReconciledFinding{
				CVEID:       cve,
				Component:   comp,
				Severity:    severity,
				Disposition: DispositionUnhandled,
				Reason:      "Waiver was explicitly rejected by maintainer",
			})
		default:
			report.Summary.Unhandled++
			report.Findings = append(report.Findings, ReconciledFinding{
				CVEID:       cve,
				Component:   comp,
				Severity:    severity,
				Disposition: DispositionUnhandled,
				Reason:      fmt.Sprintf("Waiver has unhandled status %q", matched.Status),
			})
		}
	}

	// 3. Identify fixed (remediated) waivers that were registered but are absent from fresh SBOM
	for _, w := range reg.Waivers {
		pairKey := w.CVEID + ":" + w.Component
		if !matchedWaiverPairs[pairKey] {
			report.Summary.Fixed++
			exp := ""
			if w.ExpiryDate != nil {
				exp = *w.ExpiryDate
			}
			report.Findings = append(report.Findings, ReconciledFinding{
				CVEID:       w.CVEID,
				Component:   w.Component,
				Severity:    w.Severity,
				Disposition: DispositionFixed,
				Reason:      "Finding no longer detected in target SBOM (remediated)",
				ExpiryDate:  exp,
			})
		}
	}

	// 4. Sort findings deterministically by Disposition, Severity, CVEID, Component
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Disposition != report.Findings[j].Disposition {
			return report.Findings[i].Disposition < report.Findings[j].Disposition
		}
		if report.Findings[i].CVEID != report.Findings[j].CVEID {
			return report.Findings[i].CVEID < report.Findings[j].CVEID
		}
		return report.Findings[i].Component < report.Findings[j].Component
	})

	// 5. Calculate Release Verdict
	// Fail-closed gating: 0 unhandled, 0 expired, 0 pending
	if report.Summary.Unhandled == 0 && report.Summary.Expired == 0 && report.Summary.Pending == 0 {
		report.Verdict = VerdictPass
	} else {
		report.Verdict = VerdictGated
	}

	return report, nil
}
