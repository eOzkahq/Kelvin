---
title: "P2-32 — Define Partial Assessment Completion Semantics"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/scanner-engine", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-32"
priority: "high"
status: "ready-for-dev"
---

# P2-32 — Define Partial Assessment Completion Semantics

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Represent assessments where some scanner integrations succeed while others fail or become unavailable.

---

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Assess["Assessment with Multiple Scanners (Preflight, ZAP, Nuclei)"] --> Exec["Execute Scanners"]

    subgraph Results ["Scanner Statuses"]
        S1["Preflight: SUCCESS (Findings Found)"]
        S2["ZAP Baseline: SUCCESS (Findings Found)"]
        S3["Nuclei: FAILED (Timeout / Crash)"]
    end

    Exec --> Results
    Results --> Evaluator["Assessment State Evaluator"]
    Evaluator --> Decision{"All Succeeded?"}
    Decision -- No --> CheckEssential{"Did Essential Baseline Succeed?"}
    CheckEssential -- Yes --> MarkPartial["Mark Assessment: PARTIALLY_COMPLETED"]
    CheckEssential -- No --> MarkFailed["Mark Assessment: FAILED"]
    MarkPartial --> SaveFindings["Persist Partial Findings with Degradation Warning"]
```

---

## 📋 Detailed Requirements

- Define how the system handles a profile containing multiple scanners.
- Distinguish: Fully completed assessment, Completed with warnings, Partially completed assessment, Failed assessment, Cancelled assessment.
- Preserve valid results from successful scanners.
- Record which scanners completed and which did not.
- Define whether dependent checks should continue after a scanner fails.
- Avoid presenting a partial result as a complete assessment.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Partial execution states are defined.
- [ ] Successful scanner results remain available when another scanner fails.
- [ ] Failed scanner executions have explicit status and diagnostics.
- [ ] Overall assessment status reflects the actual outcome.
- [ ] Tests cover mixed success and failure scenarios.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
