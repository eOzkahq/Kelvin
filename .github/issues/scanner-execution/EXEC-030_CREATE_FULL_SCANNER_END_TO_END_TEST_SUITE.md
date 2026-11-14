---
title: "EXEC-030 — Create Full Scanner End-to-End Test Suite"
labels: ["testing","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-030"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 8 — Staging Certification and Deployment"
---

# EXEC-030 — Create Full Scanner End-to-End Test Suite

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 8 — Staging Certification and Deployment  
**Issue ID:** `EXEC-030`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Validate the complete execution pipeline from assessment submission to result retrieval.

---

## 📐 Architecture & Workflow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Tester as Test Suite
    participant API as Kelvin API
    participant Queue as Redis Queue
    participant Worker as Worker Runner
    participant Storage as Supabase Storage
    participant DB as Supabase DB
    Tester->>API: Submit Assessment
    API->>Queue: Enqueue Task
    Queue->>Worker: Lease Job
    Worker->>Worker: Execute Container (Nuclei / ZAP)
    Worker->>Storage: Store Evidence
    Worker->>DB: Store Findings
    Tester->>API: Retrieve Results & Verify Envelope
```

---

## 📋 Detailed Requirements

- Create end-to-end tests for Nuclei and ZAP baseline against controlled targets.
- Test authorization rejections, timeout, cancellation, and Redis reconnects.
- Verify zero container or scratch workspace leaks.

---

## ✅ Acceptance Criteria

- [ ] Both Nuclei and ZAP complete end-to-end tests.
- [ ] Unauthorized target tests fail.
- [ ] Cancellation tests pass.
- [ ] Timeout tests pass.
- [ ] Redis recovery tests pass.
- [ ] Storage failure tests pass.
- [ ] No container or workspace is leaked.
