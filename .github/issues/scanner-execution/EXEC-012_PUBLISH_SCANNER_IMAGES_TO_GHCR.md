---
title: "EXEC-012 — Publish Scanner Images to GHCR"
labels: ["devops","infrastructure","kind/scanner-integration","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-012"
priority: "critical"
status: "completed"
phase: "Phase 3 — Scanner Image Release and Certification"
---

# EXEC-012 — Publish Scanner Images to GHCR

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 3 — Scanner Image Release and Certification  
**Issue ID:** `EXEC-012`  
**Priority:** `critical`  
**Status:** `completed`  

---

## 🎯 Purpose

Publish multi-arch/ARM64 scanner images to GitHub Container Registry with immutable digests.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    Build["CI Image Build"] --> Push["Push to ghcr.io/eozkull/kelvin"]
    Push --> Digest["Extract Immutable SHA256 Digest"]
    Digest --> Lock["Update Authoritative Release Lock"]
```

---

## 📋 Detailed Requirements

- Authenticate build pipeline to GHCR with minimal required token scopes.
- Push ARM64 images and publish immutable image digests.
- Prevent usage of mutable latest tags in staging and production.

---

## ✅ Acceptance Criteria

- [x] GHCR publication tooling configured for approved Nuclei image.
- [x] GHCR publication tooling configured for approved ZAP image.
- [x] Images configured for rootless execution from Oracle VM.
- [x] Release metadata captures immutable digests.
- [x] Oracle host verifies the digest before execution.
