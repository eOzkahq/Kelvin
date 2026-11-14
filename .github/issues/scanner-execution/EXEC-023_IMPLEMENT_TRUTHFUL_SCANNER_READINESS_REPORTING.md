---
title: "EXEC-023 — Implement Truthful Scanner Readiness Reporting"
labels: ["observability","backend","area/worker","priority/high"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-023"
priority: "high"
status: "ready-for-dev"
phase: "Phase 6 — Readiness, Observability and Recovery"
---

# EXEC-023 — Implement Truthful Scanner Readiness Reporting

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 6 — Readiness, Observability and Recovery  
**Issue ID:** `EXEC-023`  
**Priority:** `high`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Replace generic scanner readiness with real runtime and adapter verification.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Probe["API /health/ready & /readyz"]
    Probe --> CheckDB["Database: UP"]
    Probe --> CheckRedis["Redis TLS: UP"]
    Probe --> CheckStorage["Storage: UP"]
    Probe --> CheckRunner{"Scanner Runner Active?"}
    CheckRunner -->|Yes| RReady["scannerRunner: READY"]
    CheckRunner -->|No| RUnavail["scannerRunner: UNAVAILABLE"]
```

---

## 📋 Detailed Requirements

- Verify runtime availability, queue connection, and scanner certification.
- Keep scannerRunner: UNAVAILABLE until verified worker is active.
- Ensure health probes do not leak internal credentials or sensitive data.

---

## ✅ Acceptance Criteria

- [ ] Scanner readiness becomes healthy only when all required checks pass.
- [ ] An unavailable scanner does not appear ready.
- [ ] API and worker readiness remain distinguishable.
- [ ] Health output contains no secrets.
- [ ] Readiness updates correctly after runtime failure.
