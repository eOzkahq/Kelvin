---
title: "P2-04 — Define the Scanner Output Envelope"
labels: ["phase/2-scanner-engine", "workstream/a-foundation", "area/scanner-engine", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream A — Scanner Architecture & Integration Foundation"
issue_id: "P2-04"
priority: "high"
status: "ready-for-dev"
---

# P2-04 — Define the Scanner Output Envelope

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream A — Scanner Architecture & Integration Foundation  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Create a consistent output envelope for results and diagnostics returned by different scanner adapters.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    subgraph AdapterExecution ["Scanner Adapter"]
        Proc["Subprocess / Engine"]
    end

    subgraph EnvelopeStructure ["OutputEnvelope v1.0"]
        Meta["ScannerMetadata (ID, Version)"]
        Diag["Diagnostics (ExitCode, CPU, Memory)"]
        Raw["RawOutput (Untrusted Dump)"]
        Findings["Findings Collection (Untrusted Candidate)"]
        Status["Status (Success, Partial, Failed)"]
    end

    subgraph Consumer ["Worker Daemon"]
        Ingest["ValidateOutputEnvelope"]
        Norm["Ingestion & Canonical Normalizer"]
    end

    Proc --> Meta & Diag & Raw & Findings & Status
    Meta & Diag & Raw & Findings & Status --> Ingest --> Norm
```

---

## 📋 Detailed Requirements

- Define a common output structure containing: Assessment ID, Scanner identifier and version, Execution status, Start and completion timestamps, Findings collection, Execution diagnostics, Scanner-specific metadata, Partial-result indicator.
- Distinguish successful execution, completed-with-warnings, partial completion, and failure.
- Define how adapters represent scanner crashes and malformed output.
- Keep raw output separate from normalized findings.
- Include correlation identifiers for tracing.
- Ensure output structures are versioned.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [x] A documented, versioned output contract exists.
- [x] All adapters use the common envelope.
- [x] Failure and partial-result states are unambiguous.
- [x] Raw scanner output cannot be mistaken for normalized findings.
- [x] Contract tests validate serialization and deserialization.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Scanner Output Envelope Specification: [`docs/architecture/SCANNER_OUTPUT_ENVELOPE.md`](../../../docs/architecture/SCANNER_OUTPUT_ENVELOPE.md)
- Scanner Invocation Contract Specification: [`docs/architecture/SCANNER_INVOCATION_CONTRACT.md`](../../../docs/architecture/SCANNER_INVOCATION_CONTRACT.md)
- Scanner Adapter Interface Specification: [`docs/architecture/SCANNER_ADAPTER_INTERFACE.md`](../../../docs/architecture/SCANNER_ADAPTER_INTERFACE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scanner Output Envelope: [`docs/architecture/SCANNER_OUTPUT_ENVELOPE.md`](../../../docs/architecture/SCANNER_OUTPUT_ENVELOPE.md)
- Machine-readable schema: [`packages/schemas/scanner-output.v1.json`](../../../packages/schemas/scanner-output.v1.json)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
