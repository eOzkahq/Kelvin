---
title: "P2-39 — Implement OWASP ZAP Output Parser"
labels: ["phase/2-scanner-engine", "workstream/d-normalization", "area/scanner-engine", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream D — Result Parsing & Normalization"
issue_id: "P2-39"
priority: "high"
status: "ready-for-dev"
---

# P2-39 — Implement OWASP ZAP Output Parser

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream D — Result Parsing & Normalization  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Convert ZAP Baseline output into KELVIN's internal scanner result representation.

---

## 📋 Detailed Requirements

- Support the approved ZAP output format.
- Parse alert identifiers, names, descriptions, risk levels, affected URLs, and available evidence.
- Preserve ZAP-specific metadata.
- Handle missing optional fields.
- Reject malformed or unsupported output safely.
- Track parser and format versions.
- Keep parsing separate from scanner execution.
- Ensure extracted target references undergo scope validation.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Valid ZAP fixtures are parsed correctly.
- [ ] Missing and malformed fields are handled safely.
- [ ] ZAP metadata is preserved.
- [ ] Output conforms to the common scanner result envelope.
- [ ] Parser tests cover representative alerts and failure cases.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
