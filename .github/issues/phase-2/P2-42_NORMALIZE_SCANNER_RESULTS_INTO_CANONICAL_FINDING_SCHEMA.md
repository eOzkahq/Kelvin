---
title: "P2-42 — Normalize Scanner Results into the Canonical Finding Schema"
labels: ["phase/2-scanner-engine", "workstream/d-normalization", "area/scanner-engine", "kind/feature", "priority/critical", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream D — Result Parsing & Normalization"
issue_id: "P2-42"
priority: "critical"
status: "ready-for-dev"
---

# P2-42 — Normalize Scanner Results into the Canonical Finding Schema

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream D — Result Parsing & Normalization  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Convert scanner-specific results into the canonical finding and evidence model established in Phase 1.

---

## 📋 Detailed Requirements

- Implement a shared normalization layer.
- Map scanner-specific fields to the Phase 1 finding schema (`finding.v1.json`).
- Preserve scanner source and rule identifiers.
- Map affected target references.
- Map descriptions, evidence, and relevant metadata.
- Ensure every normalized finding references its assessment and source scanner.
- Handle incomplete records consistently.
- Avoid changing the Phase 1 canonical schema without an approved schema or ADR update.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] All MVP scanner adapters produce normalized findings.
- [ ] Normalized findings satisfy the canonical schema.
- [ ] Source scanner metadata is retained.
- [ ] Invalid records are rejected or quarantined safely.
- [ ] Contract tests verify normalized output across all integrations.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
