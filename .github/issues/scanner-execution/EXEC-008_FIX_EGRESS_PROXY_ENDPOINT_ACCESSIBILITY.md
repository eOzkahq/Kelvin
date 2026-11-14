---
title: "EXEC-008 — Fix Egress Proxy Endpoint Accessibility"
labels: ["security","backend","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-008"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 2 — Network Isolation and Egress"
---

# EXEC-008 — Fix Egress Proxy Endpoint Accessibility

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 2 — Network Isolation and Egress  
**Issue ID:** `EXEC-008`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Fix loopback-only proxy binding so scanner containers can reach the egress proxy without exposing it publicly.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    Worker["Worker Host Interface / Bridge IP"]
    Proxy["Proxy Listener (Bridge Gateway IP : Port)"]
    Scanner["Scanner Container (Separate NetNS)"]
    Scanner -->|"Connects to Gateway IP"| Proxy
    Public["Public Interface (0.0.0.0)"] -.->|Blocked / Not Bound| Proxy
```

---

## 📋 Detailed Requirements

- Replace 127.0.0.1:0 binding with a runtime-aware endpoint provider (internal bridge gateway IP).
- Do not expose proxy on public or control-plane interfaces.
- Associate proxy instances strictly with single execution contexts and ensure shutdown on completion.

---

## ✅ Acceptance Criteria

- [ ] Scanner can connect to the intended proxy endpoint.
- [ ] Proxy cannot be reached from the public internet.
- [ ] Proxy instances cannot be reused across unrelated tenants.
- [ ] Proxy is stopped after execution.
- [ ] Tests no longer assume that scanner and worker share localhost.
