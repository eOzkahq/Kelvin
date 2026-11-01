---
title: "P2-23 — Apply Scanner-Specific Network Egress Policies"
labels: ["phase/2-scanner-engine", "workstream/c-worker-orchestration", "area/security", "kind/security", "priority/critical", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream C — Worker Execution & Orchestration"
issue_id: "P2-23"
priority: "critical"
status: "ready-for-dev"
---

# P2-23 — Apply Scanner-Specific Network Egress Policies

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream C — Worker Execution & Orchestration  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Apply the Phase 1 network isolation architecture to each scanner runtime.

---

## 📋 Detailed Requirements

- Define network egress requirements for each scanner.
- Allow only the minimum network communication needed for an approved assessment.
- Ensure scanners cannot use unrestricted network access.
- Apply target scope restrictions consistently across built-in and external scanners.
- Restrict unexpected outbound callbacks and unrelated network destinations.
- Ensure scanner configuration cannot weaken network policy.
- Document how DNS resolution, redirects, and resolved network destinations are handled.
- Test policy enforcement at the execution boundary.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [ ] Each scanner has a documented egress policy.
- [ ] Scanner execution cannot bypass Phase 1 network restrictions.
- [ ] Unauthorized outbound destinations are blocked.
- [ ] Network policy failures are observable.
- [ ] Integration tests verify permitted and prohibited network behavior.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
