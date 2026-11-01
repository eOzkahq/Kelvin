---
title: "P2-27 — Integrate Scanner Progress Reporting"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/worker", "kind/feature", "priority/medium", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-27"
priority: "medium"
status: "ready-for-dev"
---

# P2-27 — Integrate Scanner Progress Reporting

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Expose meaningful execution progress from the assessment engine without depending on scanner-specific output formats.

---

## 📋 Detailed Requirements

- Define normalized execution stages: Preflight, Scanner initialization, Scanner execution, Output collection, Result normalization, Completion.
- Allow adapters to report supported progress information.
- Avoid fabricating percentage completion when a scanner cannot provide reliable progress.
- Publish progress through the existing assessment lifecycle mechanisms.
- Record stage transitions with timestamps.
- Ensure progress reporting does not expose sensitive scanner output.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [x] Assessment execution stages are observable.
- [x] Supported scanner progress is mapped consistently.
- [x] Unknown progress is represented honestly.
- [x] Stage transitions are traceable.
- [x] Tests cover normal and interrupted execution.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Scanner Progress Reporting: [docs/architecture/SCANNER_PROGRESS_REPORTING.md](../../../docs/architecture/SCANNER_PROGRESS_REPORTING.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
