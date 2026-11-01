---
title: "P2-35 — Record Immutable Assessment Execution Manifests"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/database", "kind/security", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-35"
priority: "high"
status: "ready-for-dev"
---

# P2-35 — Record Immutable Assessment Execution Manifests

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Make each assessment execution reproducible and auditable by recording the exact configuration and runtime components used.

---

## 📋 Detailed Requirements

- Create an execution manifest at assessment start.
- Record: Assessment profile and version, Scanner identifiers and versions, Scanner image digests, Ruleset or template catalog versions, Validated target reference, Effective resource and timeout limits, Execution start time.
- Ensure the manifest cannot be silently modified after execution begins.
- Record relevant configuration changes as separate events.
- Avoid storing secrets or unnecessary sensitive configuration values.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Each assessment has an execution manifest.
- [ ] Scanner and ruleset versions are traceable.
- [ ] Effective configuration is recorded.
- [ ] The manifest is protected from silent modification.
- [ ] Tests verify manifest completeness and immutability.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
