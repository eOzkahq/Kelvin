---
title: "P2-10 — Build the Scanner Adapter Conformance Test Harness"
labels: ["phase/2-scanner-engine", "workstream/a-foundation", "area/worker", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream A — Scanner Architecture & Integration Foundation"
issue_id: "P2-10"
priority: "high"
status: "ready-for-dev"
---

# P2-10 — Build the Scanner Adapter Conformance Test Harness

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream A — Scanner Architecture & Integration Foundation  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Create reusable tests that verify whether a scanner adapter follows KELVIN's integration contract.

---

## 📋 Detailed Requirements

- Build a reusable adapter test harness.
- Test initialization, configuration validation, execution, cancellation, and output handling.
- Support fake scanner processes for deterministic tests.
- Include fixtures for valid output, malformed output, empty output, partial output, and scanner failure.
- Verify that adapters preserve correlation identifiers.
- Verify that adapter errors use standard KELVIN error semantics.
- Make the harness usable by future scanner integrations.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] The harness can test any conforming adapter.
- [ ] At least one external scanner adapter and one built-in adapter pass the harness.
- [ ] Failure scenarios are covered.
- [ ] Tests run in CI without requiring unrestricted internet access.
- [ ] Usage documentation is available.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
