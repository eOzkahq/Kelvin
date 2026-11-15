---
title: "EXEC-011 — Rebuild the Scanner Image Pipeline for ARM64"
labels: ["kind/scanner-integration","devops","infrastructure","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-011"
priority: "critical"
status: "completed"
phase: "Phase 3 — Scanner Image Release and Certification"
---

# EXEC-011 — Rebuild the Scanner Image Pipeline for ARM64

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 3 — Scanner Image Release and Certification  
**Issue ID:** `EXEC-011`  
**Priority:** `critical`  
**Status:** `completed`  

---

## 🎯 Purpose

Fix scripts/scanners/build-images.sh to target linux/arm64 for Oracle Linux.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    Source["Dockerfile (ARM64)"] --> Build["Docker Buildx (--platform linux/arm64)"]
    Build --> Verify["Verify Binary ELF & Non-Root 10001"]
    Verify --> Tag["Pinned Tag & Immutable Digest"]
```

---

## 📋 Detailed Requirements

- Update build scripts to target linux/arm64 explicitly.
- Validate base images and scanner binaries are native ARM64.
- Ensure non-root execution (UID/GID 10001:10001) in built images.

---

## ✅ Acceptance Criteria

- [x] Nuclei image runs on ARM64.
- [x] ZAP image runs on ARM64.
- [x] Executable versions match declared versions.
- [x] Images run as UID/GID 10001:10001.
- [x] No unexpected architecture fallback occurs.
