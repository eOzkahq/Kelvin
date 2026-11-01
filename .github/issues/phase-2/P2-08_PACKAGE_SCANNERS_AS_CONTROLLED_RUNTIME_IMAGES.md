---
title: "P2-08 — Package Scanners as Controlled Runtime Images"
labels: ["phase/2-scanner-engine", "workstream/a-foundation", "area/infra", "kind/feature", "priority/critical", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream A — Scanner Architecture & Integration Foundation"
issue_id: "P2-08"
priority: "critical"
status: "ready-for-dev"
---

# P2-08 — Package Scanners as Controlled Runtime Images

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream A — Scanner Architecture & Integration Foundation  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Create reproducible scanner runtime environments that can be deployed consistently across development, testing, and production.

---

## 📋 Detailed Requirements

- Package external scanner dependencies in controlled container images.
- Use pinned base images and dependency versions.
- Prefer minimal runtime images.
- Avoid including unnecessary compilers, shells, debugging utilities, or unrelated packages in production images.
- Run scanner containers as non-root wherever supported.
- Define image build and verification processes.
- Record image digests and scanner versions.
- Integrate image builds into CI.
- Document vulnerability scanning and update requirements for scanner images.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [x] Reproducible ZAP and Nuclei runtime image definitions are present; production images remain unavailable until reviewed pins are supplied.
- [x] The manual CI build records scanner versions, immutable input references, and output image digests as build evidence.
- [x] Runtime images run as UID/GID 10001; builds verify read-only execution with bounded temporary storage.
- [x] CI builds, verifies reported versions, scans images, and generates SBOMs.
- [x] Image update and rollback procedures are documented.

The workflow builds but does not publish or sign images. Promotion, signing, catalog assembly, and population of release digests in `images.lock.json` are required before external scanners can be enabled.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
- Scanner Runtime Images: [`docs/architecture/SCANNER_RUNTIME_IMAGES.md`](../../../docs/architecture/SCANNER_RUNTIME_IMAGES.md)
