---
title: "P2-33 — Implement Bounded Scanner Output Capture"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/worker", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-33"
priority: "high"
status: "ready-for-dev"
---

# P2-33 — Implement Bounded Scanner Output Capture

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Capture scanner output safely without allowing excessive output to exhaust memory or storage.

---

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    Container["Scanner stdout / stderr"] --> Stream["Worker IO Pipe Reader"]
    Stream --> Ring["Bounded Circular Buffer (Max 50MB)"]

    Ring --> CheckLimit{"Exceeds 50MB?"}
    CheckLimit -- Yes --> Truncate["Inject '[OUTPUT TRUNCATED]' Marker"]
    CheckLimit -- No --> Keep["Retain Full Stream"]
    Truncate --> Compress["Gzip Compression"]
    Keep --> Compress
    Compress --> Storage["Store Encrypted Output Artifact"]
```

---

## 📋 Detailed Requirements

- Capture standard output and standard error separately.
- Define maximum output sizes.
- Support streaming or chunked collection for larger outputs.
- Detect truncated output.
- Handle invalid encodings and malformed content.
- Avoid unbounded in-memory buffering.
- Ensure output capture continues to respect cancellation and execution deadlines.
- Record whether output was complete or truncated.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Output capture is bounded.
- [ ] Large output cannot exhaust worker memory.
- [ ] Truncated output is identified.
- [ ] Standard output and error remain distinguishable.
- [ ] Tests cover empty, normal, oversized, and malformed output.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
