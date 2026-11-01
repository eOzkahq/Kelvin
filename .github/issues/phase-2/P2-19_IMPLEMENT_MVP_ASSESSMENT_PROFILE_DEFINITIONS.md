---
title: "P2-19 — Implement MVP Assessment Profile Definitions"
labels: ["phase/2-scanner-engine", "workstream/b-integrations", "area/scanner-engine", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream B — MVP Scanner Integrations"
issue_id: "P2-19"
priority: "high"
status: "ready-for-dev"
---

# P2-19 — Implement MVP Assessment Profile Definitions

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream B — MVP Scanner Integrations  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Connect Phase 1's scan profile model to the actual scanner integrations delivered in Phase 2.

---

## 📋 Detailed Requirements

- Implement the initial assessment profiles approved for the MVP.
- Map each profile to its permitted scanner adapters and configurations.
- Define scanner order and execution dependencies.
- Define which checks can run independently.
- Ensure profiles cannot exceed the platform's safety and resource policies.
- Version profile definitions.
- Validate the profile before creating scanner executions.
- Keep profile configuration independent of scanner-specific implementation details.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [x] Approved profiles can be selected for assessments.
- [x] Each profile maps to supported scanner capabilities.
- [x] Invalid or unsupported combinations are rejected.
- [x] Profile versions are traceable.
- [x] Profile execution is covered by tests.

---

## 📦 Implementation Details

- **Profile Registry (`apps/worker/internal/adapters/profiles.go`)**:
  - Implemented `AssessmentProfile`, `ScannerPhase`, and resource ceilings (`ProfileBudget`).
  - Defined the 3 approved MVP profiles: `kelvin.profile.passive.v1`, `kelvin.profile.standard.v1`, and `kelvin.profile.deep.v1`.
  - Mapped supported scanner capabilities (`http_preflight`, `tls_assessor`, `http_security_headers`, `zap`, `nuclei`) and phased execution dependencies.
  - Implemented `GetAssessmentProfile`, `ValidateProfileSelection`, and `ListAssessmentProfiles` with default-deny validation.
- **Unit Test Coverage (`apps/worker/internal/adapters/profiles_test.go`)**:
  - Validates profile attributes, budgets, scanner whitelisting, invalid scanner rejection, and dependency phase ordering.
- **Architecture Documentation**:
  - [`docs/architecture/MVP_ASSESSMENT_PROFILES.md`](../../../docs/architecture/MVP_ASSESSMENT_PROFILES.md)

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
- MVP Assessment Profiles: [`docs/architecture/MVP_ASSESSMENT_PROFILES.md`](../../../docs/architecture/MVP_ASSESSMENT_PROFILES.md)
