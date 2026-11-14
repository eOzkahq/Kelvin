---
title: "EXEC-012 — Publish Scanner Images to GHCR"
labels: ["devops","infrastructure","kind/scanner-integration","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-012"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 3 — Scanner Image Release and Certification"
---

# EXEC-012 — Publish Scanner Images to GHCR

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 3 — Scanner Image Release and Certification  
**Issue ID:** `EXEC-012`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Publish multi-arch/ARM64 scanner images to GitHub Container Registry with immutable digests.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    Build["CI Image Build"] --> Push["Push to ghcr.io/inkesk-dozing/kelvin-scanners"]
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

- [ ] GHCR contains the approved Nuclei image.
- [ ] GHCR contains the approved ZAP image.
- [ ] Images are pullable from Oracle VM.
- [ ] Release metadata contains immutable digests.
- [ ] Oracle can verify the digest before execution.
