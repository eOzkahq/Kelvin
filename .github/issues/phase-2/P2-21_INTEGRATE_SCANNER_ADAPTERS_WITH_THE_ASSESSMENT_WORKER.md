---
title: "P2-21 — Integrate Scanner Adapters with the Assessment Worker"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/worker", "kind/feature", "priority/critical", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-21"
priority: "critical"
status: "ready-for-dev"
---

# P2-21 — Integrate Scanner Adapters with the Assessment Worker

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Connect the Phase 1 assessment worker and queue foundations to the scanner adapter system.

---

---

## 📐 Architecture & Workflow Diagram

```mermaid
sequenceDiagram
    participant Redis as Redis Job Queue
    participant Worker as Assessment Worker
    participant Reg as Scanner Registry
    participant Adapter as Scanner Adapter
    participant OCI as Container Runtime

    Redis->>Worker: Dequeue Assessment Job
    Worker->>Reg: Resolve Adapters for Selected Profile
    Reg-->>Worker: Return Adapter Instances
    loop For Each Scanner in Pipeline
        Worker->>Adapter: Execute(ctx, input)
        Adapter->>OCI: Run Isolated Scan
        OCI-->>Adapter: Raw Output
        Adapter-->>Worker: ScannerOutputEnvelope
    end
    Worker->>Worker: Aggregate Findings & Update Assessment State
```

---

## 📋 Detailed Requirements

- Resolve scanner adapters from the registry.
- Load the validated assessment execution context.
- Execute the scanners selected by the assessment profile.
- Use existing Phase 1 job lifecycle and queue contracts.
- Keep worker orchestration separate from scanner-specific logic.
- Ensure failures are reported through the established lifecycle.
- Preserve assessment and tenant context throughout execution.
- Prevent workers from accepting unvalidated execution requests.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Assessment jobs can trigger registered scanner adapters.
- [ ] Existing Phase 1 lifecycle semantics are preserved.
- [ ] Worker execution is independent of scanner implementation details.
- [ ] Failures are reflected in the established job state model.
- [ ] Integration tests cover complete worker execution.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
