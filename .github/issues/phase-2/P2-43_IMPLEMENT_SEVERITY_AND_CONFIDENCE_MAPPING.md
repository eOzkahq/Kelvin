---
title: "P2-43 — Implement Severity and Confidence Mapping"
labels: ["phase/2-scanner-engine", "workstream/d-normalization", "area/scanner-engine", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream D — Result Parsing & Normalization"
issue_id: "P2-43"
priority: "high"
status: "ready-for-dev"
---

# P2-43 — Implement Severity and Confidence Mapping

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream D — Result Parsing & Normalization  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Translate scanner-specific severity and confidence indicators into KELVIN's common classification model.

---

## 📋 Detailed Requirements

- Define mappings from each scanner's severity levels to KELVIN's canonical severity values (`INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- Document differences between scanner severity models.
- Preserve original scanner severity.
- Define how confidence or certainty is represented (`LOW`, `MEDIUM`, `HIGH`, `CONFIRMED`).
- Avoid assigning unsupported confidence values.
- Handle missing or unknown severity explicitly.
- Version the mapping rules.
- Keep advanced business risk scoring and cross-finding prioritization deferred to Phase 3.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Every MVP scanner has a documented severity mapping.
- [ ] Original scanner severity remains available.
- [ ] Unknown severity is handled consistently.
- [ ] Confidence is not fabricated when unavailable.
- [ ] Mapping tests cover all supported values.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
