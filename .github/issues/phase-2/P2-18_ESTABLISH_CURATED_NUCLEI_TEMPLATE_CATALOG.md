---
title: "P2-18 — Establish a Curated Nuclei Template Catalog"
labels: ["phase/2-scanner-engine", "workstream/b-integrations", "area/security", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 2 — Assessment Engine & Scanner Integrations"
parent_issue: "../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md"
workstream: "Workstream B — MVP Scanner Integrations"
issue_id: "P2-18"
priority: "high"
status: "ready-for-dev"
---

# P2-18 — Establish a Curated Nuclei Template Catalog

**Parent Epic:** [ISSUE-03: MVP Definition, Scope Bifurcation & Phase 2 Scanner Engine Execution Plan](../ISSUE-03_MVP_AND_PHASE_BIFURCATION.md)  
**Milestone:** [Phase 2 — Assessment Engine & Scanner Integrations](../MILESTONE_PHASE_2.md)  
**Workstream:** Workstream B — MVP Scanner Integrations  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Define a controlled collection of Nuclei templates that KELVIN permits in its MVP assessments.

---

## 📋 Detailed Requirements

- Establish a template review and approval process.
- Include only templates that satisfy the MVP's safety requirements.
- Review template request behavior, external interactions, and potential impact.
- Exclude intrusive, destructive, denial-of-service, and exploit-oriented templates from the default catalog.
- Record template identifiers, sources, versions, and review status.
- Define an update and rollback process.
- Ensure template changes are reviewed and tested before release.
- Prevent unreviewed upstream changes from being loaded automatically.

---

## 🛡️ Security & Architectural Invariants

- **Execution Isolation:** All external scanner execution must adhere strictly to ADR-0005 (Rootless OCI container workers, non-root `UID 10001`, dropped capabilities).
- **Scope Enforcement:** Scanners must never access or follow targets outside the validated scope context established in Phase 1.
- **Resource Constraints:** Timeouts, request pacing, and memory/CPU limits must be strictly applied at the worker runtime boundary.
- **Data Integrity:** Outputs must be treated as untrusted and normalized into Kelvin's Canonical Finding Schema (`finding.v1.json`, ADR-0002).

---

## ✅ Acceptance Criteria

- [x] A versioned, curated catalog exists.
- [x] Each included template has review metadata.
- [x] Disallowed templates cannot be selected.
- [x] Template catalog changes are traceable.
- [x] CI or an equivalent validation process verifies catalog integrity.

## Implementation Notes

- Created curated catalog `kelvin.safe.web.v1` in `deploy/scanners/templates/kelvin.safe.web.v1` containing approved non-intrusive safe checks (`git-config`, `env-file`, `robots-txt`, `security-txt`) with cryptographic SHA-256 integrity verification.
- Added catalog manifest `catalog.json` establishing review metadata, approval status, permitted HTTP methods (read-only `GET`), and disallowing intrusive, destructive, or DoS payloads.
- Implemented `CuratedCatalogManifest` loader and validator with automated test harness in `apps/worker/internal/adapters/nuclei_catalog.go` and `nuclei_catalog_test.go`.
- Updated Nuclei Dockerfile to package the curated templates at `/opt/kelvin/templates/kelvin.safe.web.v1`.
- Documented catalog governance and update/rollback policy in `docs/architecture/CURATED_NUCLEI_TEMPLATE_CATALOG.md`.

---

## 🔗 Related Documentation & Links

- Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
- Target Scope Enforcement: [`docs/architecture/TARGET_SCOPE_ENFORCEMENT.md`](../../../docs/architecture/TARGET_SCOPE_ENFORCEMENT.md)
- Worker Execution Isolation: [`docs/architecture/EXECUTION_ISOLATION.md`](../../../docs/architecture/EXECUTION_ISOLATION.md)
- Canonical Finding Schema: [`docs/architecture/FINDING_SCHEMA.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Scan Profiles Specification: [`docs/architecture/SCAN_PROFILES.md`](../../../docs/architecture/SCAN_PROFILES.md)
- Curated Nuclei Template Catalog: [`docs/architecture/CURATED_NUCLEI_TEMPLATE_CATALOG.md`](../../../docs/architecture/CURATED_NUCLEI_TEMPLATE_CATALOG.md)
