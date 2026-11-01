---
title: "P2-24 — Apply Scanner-Specific Resource Limits"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/worker", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-24"
priority: "high"
status: "ready-for-dev"
---

# P2-24 — Apply Scanner-Specific Resource Limits

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Configure and enforce resource constraints for the different scanner runtimes.

---

## 📋 Detailed Requirements

- Define CPU, memory, process, and temporary-storage limits for each scanner.
- Establish safe defaults and configurable platform-level ceilings.
- Ensure scanner-specific settings cannot exceed platform limits.
- Capture resource exhaustion as a structured execution failure.
- Define behavior when a scanner exceeds its resource budget.
- Prevent a single assessment from monopolizing worker resources.
- Document the expected resource requirements for each scanner.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [x] Each scanner has approved resource limits (`docs/architecture/SCANNER_RESOURCE_LIMITS.md`).
- [x] Limits are enforced by the execution environment (`apps/worker/internal/limits/limits.go`, `apps/worker/internal/sandbox/oci.go`, `apps/worker/internal/daemon/orchestrator.go`).
- [x] Resource exhaustion is reported consistently (OOM exit 137, deadline exit 124, Prometheus `ViolationOOM`/`ViolationDeadline` metrics).
- [x] User configuration cannot bypass platform ceilings (`limits.ValidateAgainstCeiling` fails closed with `ErrExceedsCeiling`).
- [x] Tests verify enforcement and failure handling (`apps/worker/internal/limits/limits_test.go`, `apps/worker/internal/daemon/orchestrator_test.go`).

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Scanner Resource Limits: [`docs/architecture/SCANNER_RESOURCE_LIMITS.md`](../../../docs/architecture/SCANNER_RESOURCE_LIMITS.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
