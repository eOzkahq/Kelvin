---
title: "EXEC-022 — Complete Evidence and Report Persistence"
labels: ["backend","security","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-022"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 5 — Queue, Job Lifecycle and Persistence"
---

# EXEC-022 — Complete Evidence and Report Persistence

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 5 — Queue, Job Lifecycle and Persistence  
**Issue ID:** `EXEC-022`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Connect scanner output to Supabase private storage and database persistence pipeline.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    RawOutput["Raw Scan Report"] --> Hash["Compute SHA256 Checksum"]
    RawOutput --> Upload["Pre-Signed TLS PUT to Supabase Storage"]
    Upload --> Bucket["Private Storage (kelvin-evidence)"]
    Hash --> DB["Supabase DB Record (status=COMPLETED, evidence_sha256)"]
```

---

## 📋 Detailed Requirements

- Store raw evidence in private kelvin-evidence bucket using tenant-scoped paths.
- Upload via short-lived pre-signed TLS URLs without exposing storage keys to runner.
- Verify checksum and ensure clean local scratch space.

---

## ✅ Acceptance Criteria

- [ ] Evidence upload and download work.
- [ ] Report upload and download work.
- [ ] Cross-tenant access is denied.
- [ ] Evidence hashes match uploaded content.
- [ ] No public bucket access is required.
- [ ] Storage failures are retriable without duplicating records.
