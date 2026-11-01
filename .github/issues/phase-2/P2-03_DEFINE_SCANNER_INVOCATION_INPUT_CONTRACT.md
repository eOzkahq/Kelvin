---
title: "P2-03 — Define the Scanner Invocation Input Contract"
labels: ["phase/2-scanner-engine", "workstream/a-foundation", "area/scanner-engine", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream A — Scanner Architecture & Integration Foundation"
issue_id: "P2-03"
priority: "high"
status: "ready-for-dev"
---

# P2-03 — Define the Scanner Invocation Input Contract

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream A — Scanner Architecture & Integration Foundation  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Define exactly what information a scanner receives when KELVIN requests an assessment.

---

## 📋 Detailed Requirements

- Define the scanner execution input structure (`ExecutionInput`).
- Include: Assessment ID, Tenant and authorization context where required, Canonical target information, Approved scope, Selected scan profile, Scanner-specific configuration, Execution deadline, Resource policy reference, Correlation and tracing identifiers.
- Ensure scanners receive only the information required for their task.
- Do not pass unrestricted user-supplied command-line arguments to scanner processes.
- Define how sensitive configuration and credentials, if supported later, are referenced without exposing secret values.
- Ensure all target data originates from the validated assessment context established in Phase 1.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [x] A versioned execution input contract exists.
- [x] Required and optional fields are documented.
- [x] Invalid or incomplete inputs are rejected.
- [x] Inputs cannot override Phase 1 authorization or scope restrictions.
- [x] Contract tests cover valid and invalid payloads.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Scanner Invocation Input Contract: [`docs/architecture/SCANNER_INVOCATION_INPUT.md`](../../../docs/architecture/SCANNER_INVOCATION_INPUT.md)
- Machine-readable schema: [`packages/schemas/scanner-invocation.v1.json`](../../../packages/schemas/scanner-invocation.v1.json)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
