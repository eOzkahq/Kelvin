---
title: "EXEC-017 — Integrate Production Nuclei Scanner Execution"
labels: ["kind/scanner-integration","backend","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-017"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 4 — Nuclei and ZAP Integration"
---

# EXEC-017 — Integrate Production Nuclei Scanner Execution

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 4 — Nuclei and ZAP Integration  
**Issue ID:** `EXEC-017`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Complete production-ready Nuclei execution pipeline with rate limits, scoped egress, and JSONL capture.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Job["Nuclei Job"] --> Limit["Apply Concurrency & Rate Limits"]
    Limit --> Container["Launch Sandboxed Container"]
    Container --> Egress["Route via Scoped Proxy"]
    Egress --> Stream["Capture JSONL Stream"]
    Stream --> Normalize["Normalize into Kelvin Envelope"]
```

---

## 📋 Detailed Requirements

- Execute certified Nuclei image with curated template catalog.
- Disable auto-update and OAST; enforce rate limits and timeout.
- Normalize JSONL stream into canonical Kelvin finding envelope.

---

## ✅ Acceptance Criteria

- [ ] Nuclei executes only against authorized targets.
- [ ] Scanner uses the approved template set.
- [ ] Scanner output is parsed without data loss.
- [ ] Rate and timeout limits are enforced.
- [ ] Scanner errors are distinguishable from zero findings.
- [ ] End-to-end integration tests pass.
