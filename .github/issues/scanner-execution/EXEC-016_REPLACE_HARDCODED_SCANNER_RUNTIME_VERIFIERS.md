---
title: "EXEC-016 — Replace Hardcoded Scanner Runtime Verifiers"
labels: ["security","kind/scanner-integration","backend","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-016"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 3 — Scanner Image Release and Certification"
---

# EXEC-016 — Replace Hardcoded Scanner Runtime Verifiers

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 3 — Scanner Image Release and Certification  
**Issue ID:** `EXEC-016`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Replace static/hardcoded scanner runtime verifiers with real cryptographic verification.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    Adapter["Scanner Adapter"] --> Inspect["Inspect Actual Image & Executable"]
    Inspect --> VerifyDigest["Verify SHA256 vs Release Lock"]
    Inspect --> VerifyVersion["Verify Binary Version Output"]
    VerifyDigest & VerifyVersion --> Report["Structured Verification Result"]
    Report --> Readiness["Worker Readiness Probe"]
```

---

## 📋 Detailed Requirements

- Inspect actual container image digests and binary versions at runtime.
- Verify Nuclei catalog digest dynamically.
- Surface verification failures to worker readiness probes.

---

## ✅ Acceptance Criteria

- [ ] A wrong image digest causes verification failure.
- [ ] A wrong executable version causes verification failure.
- [ ] A wrong catalog digest causes verification failure.
- [ ] No hardcoded verifier can mark an arbitrary runtime as certified.
- [ ] Provenance records reflect actual runtime measurements.
