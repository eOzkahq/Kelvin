---
title: "EXEC-010 — Add Network Bypass and Isolation Regression Tests"
labels: ["security","testing","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-010"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 2 — Network Isolation and Egress"
---

# EXEC-010 — Add Network Bypass and Isolation Regression Tests

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 2 — Network Isolation and Egress  
**Issue ID:** `EXEC-010`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Create comprehensive integration test suite proving scanner containers cannot bypass the egress proxy.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Suite["Network Bypass Test Suite"]
    Suite --> T1["1. Direct HTTP/HTTPS without proxy"]
    Suite --> T2["2. Localhost & RFC1918 access"]
    Suite --> T3["3. Cloud metadata 169.254.169.254"]
    Suite --> T4["4. Out-of-scope targets & redirects"]
    Suite --> T5["5. DNS rebinding"]
    Suite --> T6["6. Proxy shutdown during run"]
```

---

## 📋 Detailed Requirements

- Implement integration tests using real container network namespaces.
- Verify direct egress is dropped while authorized proxy requests succeed.
- Verify denial of cloud metadata, private IP ranges, and unauthorized hosts.

---

## ✅ Acceptance Criteria

- [ ] All bypass tests fail safely.
- [ ] All authorized proxy tests pass.
- [ ] Network tests use real container namespaces, not only mocked HTTP clients.
- [ ] Security regression tests run before scanner release.
