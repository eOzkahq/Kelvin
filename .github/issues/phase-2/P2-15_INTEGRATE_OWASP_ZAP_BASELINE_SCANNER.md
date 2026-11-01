---
title: "P2-15 — Integrate OWASP ZAP Baseline Scanner"
labels: ["phase/2-scanner-engine", "workstream/b-integrations", "area/scanner-engine", "kind/scanner-integration", "priority/critical", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream B — MVP Scanner Integrations"
issue_id: "P2-15"
priority: "critical"
status: "ready-for-dev"
---

# P2-15 — Integrate OWASP ZAP Baseline Scanner

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream B — MVP Scanner Integrations  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Integrate OWASP ZAP Baseline as the first external web application security scanner.

---

## 📋 Detailed Requirements

- Implement a Go adapter for the approved ZAP runtime.
- Pass only validated targets and approved scanner configuration.
- Collect scanner output through the defined output contract.
- Capture scanner version and execution metadata.
- Support bounded execution time and cancellation.
- Handle non-zero exit codes and malformed output.
- Ensure the integration uses the approved baseline mode.
- Prevent direct user access to arbitrary ZAP command-line options.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] ZAP Baseline can execute through KELVIN's worker architecture.
- [ ] Results are captured and returned through the common output envelope.
- [ ] Execution limits and cancellation work.
- [ ] Scanner version is recorded.
- [x] Automated adapter tests pass.

## Implementation Notes

- The worker now builds a fixed `zap-baseline.py` argv, requests the JSON report at a fixed tmpfs path, and copies that bounded report before container cleanup.
- The report normalizer validates the reported scanner version and produces Kelvin findings plus a versioned output envelope. Scanner-reported instance URLs and raw report evidence are excluded from findings.
- The reviewed image lock is still `not-released`; no approved ZAP version or image digest is available. The current worker also lacks Phase 1 scope-context loading and scoped egress, and the queue has no output-envelope storage contract. Live execution and result delivery remain gated on those integrations.
- See [ZAP Baseline Integration](../../../docs/architecture/ZAP_BASELINE_INTEGRATION.md) for the fixed invocation, report handling, and release gates.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
