---
title: "EXEC-013 — Repair Scanner Image Workflow Gating"
labels: ["devops","testing","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-013"
priority: "critical"
status: "completed"
phase: "Phase 3 — Scanner Image Release and Certification"
---

# EXEC-013 — Repair Scanner Image Workflow Gating

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 3 — Scanner Image Release and Certification  
**Issue ID:** `EXEC-013`  
**Priority:** `critical`  
**Status:** `completed`  

---

## 🎯 Purpose

Fix GitHub Actions scanner-images.yml workflow gating syntax and permissions.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Trigger["Workflow Dispatch / Tag Event"] --> ValidateInputs["Validate Inputs & Gating"]
    ValidateInputs --> Build["Build & Scan Image"]
    Build --> Gate{"Release Review Gate"}
    Gate -->|Approved| Publish["Publish to Registry"]
    Gate -->|Unapproved| ArtifactOnly["Save Ephemeral Artifact"]
```

---

## 📋 Detailed Requirements

- Replace invalid env.ENABLE_CI job condition with supported vars/inputs condition.
- Prevent unreviewed runs from publishing certified images.
- Enforce least-privilege workflow permissions.

---

## ✅ Acceptance Criteria

- [x] GitHub Actions workflow parses successfully.
- [x] Manual workflow dispatch works.
- [x] Invalid input is rejected.
- [x] Unapproved workflows cannot publish release images.
- [x] Workflow permissions are least-privilege.
