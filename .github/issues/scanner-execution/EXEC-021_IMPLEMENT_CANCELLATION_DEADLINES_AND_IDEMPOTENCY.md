---
title: "EXEC-021 — Implement Cancellation, Deadlines and Idempotency"
labels: ["backend","area/worker","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-021"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 5 — Queue, Job Lifecycle and Persistence"
---

# EXEC-021 — Implement Cancellation, Deadlines and Idempotency

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 5 — Queue, Job Lifecycle and Persistence  
**Issue ID:** `EXEC-021`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Make scanner execution safely cancellable, deadline-bounded, and idempotent.

---

## 📐 Architecture & Workflow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor User as User / API
    participant Redis as Redis Stream
    participant Daemon as Daemon Orchestrator
    participant Sandbox as Sandbox Container
    User->>Redis: Publish Cancel Command(JobID)
    Redis->>Daemon: Context Cancelled
    Daemon->>Sandbox: SIGTERM -> Grace (5s) -> SIGKILL
    Daemon->>Sandbox: Cleanup Workspace & Remove Container
    Daemon->>Redis: XACK Cancelled State
```

---

## 📋 Detailed Requirements

- Propagate cancellation signals from API through Redis to container executor.
- Enforce hard execution deadlines with 5s/10s grace periods before SIGKILL.
- Ensure idempotency and avoid duplicate findings upon retries.

---

## ✅ Acceptance Criteria

- [ ] Cancellation stops the actual container.
- [ ] Timed-out jobs become terminal.
- [ ] Retried jobs do not duplicate persisted findings.
- [ ] Interrupted jobs have deterministic recovery behavior.
- [ ] Cleanup is verified by integration tests.
