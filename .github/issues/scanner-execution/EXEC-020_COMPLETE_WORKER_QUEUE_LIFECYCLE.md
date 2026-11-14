---
title: "EXEC-020 — Complete Worker Queue Lifecycle"
labels: ["area/worker","backend","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-020"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 5 — Queue, Job Lifecycle and Persistence"
---

# EXEC-020 — Complete Worker Queue Lifecycle

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 5 — Queue, Job Lifecycle and Persistence  
**Issue ID:** `EXEC-020`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Harden Redis stream queue processing, consumer groups, claims, and crash recovery.

---

## 📐 Architecture & Workflow Diagram

```mermaid
sequenceDiagram
    autonumber
    participant Worker as Worker Runner
    participant Redis as Redis Streams (TLS)
    participant DB as Supabase DB
    Worker->>Redis: XREADGROUP Claim Job
    Worker->>Worker: Execute Sandboxed Scan
    Worker->>DB: Persist Results & Findings
    Worker->>Redis: XACK Job Completed
    Note over Worker,Redis: If Worker crashes before XACK, job is recovered via XAUTOCLAIM
```

---

## 📋 Detailed Requirements

- Implement robust claim and acknowledgement semantics via Redis consumer groups.
- Implement dead-letter queueing and bounded retries.
- Prevent duplicate execution and safely recover interrupted jobs upon restart.

---

## ✅ Acceptance Criteria

- [ ] A job is not silently lost.
- [ ] A job is not acknowledged before successful persistence.
- [ ] Duplicate delivery does not duplicate completed results.
- [ ] Retry exhaustion moves a job to a terminal failure state.
- [ ] Worker restarts recover eligible jobs safely.
