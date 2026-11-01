---
title: "P2-11 — Implement the HTTP/HTTPS Preflight Assessment Adapter"
labels: ["phase/2-scanner-engine", "workstream/b-integrations", "area/scanner-engine", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream B — MVP Scanner Integrations"
issue_id: "P2-11"
priority: "high"
status: "ready-for-dev"
---

# P2-11 — Implement the HTTP/HTTPS Preflight Assessment Adapter

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream B — MVP Scanner Integrations  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Implement a built-in adapter that verifies whether an approved web target is reachable before more expensive scanner execution begins.

---

## 📋 Detailed Requirements

- Support approved HTTP and HTTPS targets.
- Perform bounded connection and response checks.
- Capture response status, protocol information, and relevant timing metadata.
- Handle connection failures, TLS failures, and timeout conditions.
- Respect the validated target and redirect restrictions from Phase 1.
- Avoid crawling or recursively discovering unrelated targets.
- Record clear preflight outcomes.
- Ensure preflight checks cannot bypass the approved target scope.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [x] The adapter supports approved HTTP/HTTPS targets through the Phase 1 scope policy provider.
- [x] Reachability, TLS/connection failure, timeout, and cancellation states use the common output envelope.
- [x] Redirects are revalidated by the scope-aware HTTP client before follow-up requests.
- [x] Requests and total execution are bounded by scanner config and the task deadline.
- [x] Local HTTP/TLS tests cover response capture, out-of-scope redirect, TLS failure, timeout, and invalid input.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
- HTTP/HTTPS Preflight Adapter: [`docs/architecture/HTTP_PREFLIGHT_ADAPTER.md`](../../../docs/architecture/HTTP_PREFLIGHT_ADAPTER.md)
