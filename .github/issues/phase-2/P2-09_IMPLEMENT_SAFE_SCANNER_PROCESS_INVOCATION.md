---
title: "P2-09 — Implement Safe Scanner Process Invocation"
labels: ["phase/2-scanner-engine", "workstream/a-foundation", "area/security", "kind/feature", "priority/critical", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream A — Scanner Architecture & Integration Foundation"
issue_id: "P2-09"
priority: "critical"
status: "ready-for-dev"
---

# P2-09 — Implement Safe Scanner Process Invocation

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream A — Scanner Architecture & Integration Foundation  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Provide one controlled mechanism for invoking external scanner processes without creating command-injection vulnerabilities.

---

## 📋 Detailed Requirements

- Implement a shared Go process invocation abstraction.
- Use structured executable paths and argument arrays.
- Never construct scanner commands through shell string concatenation.
- Do not allow arbitrary executables or user-supplied shell commands.
- Validate arguments against each scanner's supported configuration.
- Support execution deadlines and cancellation.
- Capture standard output and standard error with bounded buffers.
- Record exit codes and execution metadata.
- Ensure processes inherit only the minimum required environment variables.
- Avoid leaking secrets through process arguments or logs.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] External scanners are invoked through the shared abstraction.
- [ ] Shell-based command construction is not used.
- [ ] Argument validation is enforced.
- [ ] Timeouts and cancellation are supported.
- [ ] Output capture is bounded.
- [ ] Tests cover malicious input, invalid arguments, and process failures.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
