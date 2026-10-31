---
title: "P2-20 — Implement Scanner Availability and Runtime Readiness Checks"
labels: ["phase/2-scanner-engine", "workstream/b-integrations", "area/worker", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream B — MVP Scanner Integrations"
issue_id: "P2-20"
priority: "high"
status: "ready-for-dev"
---

# P2-20 — Implement Scanner Availability and Runtime Readiness Checks

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream B — MVP Scanner Integrations  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Ensure that KELVIN can determine whether each scanner is ready before attempting execution.

---

## 📋 Detailed Requirements

- Verify required scanner binaries or runtime images are available.
- Verify scanner version compatibility.
- Verify required configuration and template catalogs exist.
- Detect missing or corrupted runtime dependencies.
- Expose scanner-specific readiness information through the appropriate internal health interfaces.
- Distinguish application health from individual scanner availability.
- Prevent unavailable scanners from being selected for new executions.
- Avoid exposing internal runtime details through public health endpoints.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Scanner readiness can be evaluated independently.
- [ ] Missing dependencies are detected before execution.
- [ ] Unavailable scanners are reported accurately.
- [ ] Readiness failures are logged with correlation information.
- [ ] Tests cover missing, incompatible, and ready scanner states.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
