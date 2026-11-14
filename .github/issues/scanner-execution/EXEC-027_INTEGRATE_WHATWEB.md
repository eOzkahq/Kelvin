---
title: "EXEC-027 — Integrate WhatWeb"
labels: ["kind/scanner-integration","priority/high"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-027"
priority: "high"
status: "ready-for-dev"
phase: "Phase 7 — Additional Scanner Integrations"
---

# EXEC-027 — Integrate WhatWeb

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 7 — Additional Scanner Integrations  
**Issue ID:** `EXEC-027`  
**Priority:** `high`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Integrate WhatWeb for web technology fingerprinting under proxy egress.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    Task["WhatWeb Task"] --> Sandbox["Sandboxed WhatWeb Container"]
    Sandbox --> Proxy["Scoped Egress Proxy"]
    Sandbox --> Parser["Normalize Technologies & Versions"]
```

---

## 📋 Detailed Requirements

- Pin immutable image and enforce request limits.
- Route all requests through scoped egress proxy.
- Normalize technologies, versions, and headers into findings.

---

## ✅ Acceptance Criteria

- [ ] Only approved web targets are scanned.
- [ ] Scanner requests are rate-limited.
- [ ] Results use the common schema.
- [ ] Runtime identity is verified.
