---
title: "EXEC-003 — Reconcile Scanner Image and Template Release Manifests"
labels: ["devops","security","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-003"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 0 — Architecture and Repository Audit"
---

# EXEC-003 — Reconcile Scanner Image and Template Release Manifests

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 0 — Architecture and Repository Audit  
**Issue ID:** `EXEC-003`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Resolve manifest conflicts between deploy/scanner-image-lock.yaml and deploy/scanners/images.lock.json.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    Source["Verified Build Artifacts"] --> ManifestGen["Canonical Release Manifest Generator"]
    ManifestGen --> LockFile["Authoritative Release Lock"]
    LockFile --> CIValidation{"CI Consistency Gate"}
    CIValidation -->|Pass| ReleaseApproved["Production Certification"]
    CIValidation -->|Fail (Empty/Mismatch)| Reject["Build Terminated"]
```

---

## 📋 Detailed Requirements

- Establish one canonical release manifest as the single source of truth.
- Define schema and version for image digests and template catalog digests.
- Ensure catalog digest represents verified deterministic hashes of catalog files.
- Remove manual conflicting lock entries and fail CI on unverified manifests.

---

## ✅ Acceptance Criteria

- [ ] There is one authoritative source of release status.
- [ ] An unreleased scanner cannot be used by a production worker.
- [ ] Empty or missing digests fail validation.
- [ ] Conflicting manifest files fail CI.
- [ ] Every certified image and catalog is traceable to a build record.
