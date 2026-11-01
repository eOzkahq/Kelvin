---
title: "P2-29 — Implement Per-Target Request Pacing"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/security", "kind/security", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-29"
priority: "high"
status: "ready-for-dev"
---

# P2-29 — Implement Per-Target Request Pacing

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Control the rate at which scanners send requests to a target.

---

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Scanner["Scanner Adapter Request Engine"] --> TokenBucket["Token Bucket Rate Limiter"]

    subgraph PacingRules ["Pacing Configuration"]
        P1["Max Requests Per Second (e.g. 10 req/s)"]
        P2["Burst Capacity Limit"]
        P3["Jitter & Backoff on HTTP 429 / 503"]
    end

    TokenBucket --> PacingRules
    PacingRules --> Gate{"Token Available?"}
    Gate -- Yes --> Send["Transmit HTTP Request to Target"]
    Gate -- No --> Wait["Delay Until Next Token Refill"]
    Wait --> Send
```

---

## 📋 Detailed Requirements

- Define request pacing defaults for each scanner.
- Support platform-enforced request-rate ceilings.
- Apply limits consistently to built-in checks and scanner adapters.
- Prevent users from setting rates above approved limits.
- Define how redirects and requests to discovered URLs are accounted for.
- Distinguish request pacing from worker concurrency.
- Record throttling events where useful for diagnostics.
- Document how pacing affects assessment duration.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Request-rate limits are enforced.
- [ ] Scanner configuration cannot bypass platform ceilings.
- [ ] Per-target pacing is applied consistently.
- [ ] Throttling behavior is testable and observable.
- [ ] Tests verify rate enforcement under concurrent execution.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
