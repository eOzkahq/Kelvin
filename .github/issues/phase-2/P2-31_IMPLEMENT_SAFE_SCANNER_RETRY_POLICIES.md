---
title: "P2-31 — Implement Safe Scanner Retry Policies"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/worker", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-31"
priority: "high"
status: "ready-for-dev"
---

# P2-31 — Implement Safe Scanner Retry Policies

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Define when scanner execution may be retried without creating uncontrolled repeated target traffic or duplicate assessment results.

---

## 📋 Detailed Requirements

- Define retry policies per scanner and failure category.
- Retry only failures classified as safe and transient.
- Do not retry invalid configuration, authorization failures, or scope violations.
- Use bounded retry counts and backoff.
- Respect assessment deadlines and request budgets.
- Integrate with Phase 1 idempotency and recovery semantics.
- Record each retry attempt and its reason.
- Prevent queue redelivery from creating uncontrolled repeated execution.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Retry rules are documented and implemented.
- [ ] Retry attempts are bounded.
- [ ] Non-retryable failures are not retried.
- [ ] Retries respect deadlines and resource limits.
- [ ] Tests cover transient failure, permanent failure, and repeated delivery.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
