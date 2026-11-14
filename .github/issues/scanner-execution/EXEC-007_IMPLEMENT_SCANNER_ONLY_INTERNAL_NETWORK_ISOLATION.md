---
title: "EXEC-007 — Implement Scanner-Only Internal Network Isolation"
labels: ["security","infrastructure","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-007"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 2 — Network Isolation and Egress"
---

# EXEC-007 — Implement Scanner-Only Internal Network Isolation

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 2 — Network Isolation and Egress  
**Issue ID:** `EXEC-007`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Prevent scanner containers from directly accessing the internet or internal infrastructure.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Scanner["Scanner Container"]
    Proxy["Scoped Egress Proxy"]
    Host["Host / Internal Network"]
    CloudMetadata["IMDS 169.254.169.254"]
    Internet["Public Target"]
    
    Scanner -->|"Direct Traffic"| Firewall{"Host Firewall / Bridge Isolation"}
    Firewall -->|Direct Internet| DROP1["DROP (Blocked)"]
    Firewall -->|10/8, 172/12, 192/168| DROP2["DROP (Blocked)"]
    Firewall -->|169.254.169.254| DROP3["DROP (Blocked)"]
    Scanner -->|"Proxy Port Only"| Proxy
    Proxy -->|"Validated Allowlist Egress"| Internet
```

---

## 📋 Detailed Requirements

- Isolate scanner network namespace: direct outbound connections must be rejected.
- Block access to RFC1918 private ranges and cloud metadata endpoints (169.254.169.254).
- Permit communication only to the designated egress proxy endpoint.
- Separate control plane network from scanner execution network.

---

## ✅ Acceptance Criteria

- [ ] Direct outbound HTTP and HTTPS from a scanner container fails.
- [ ] Access to private IP ranges and cloud metadata endpoints fails.
- [ ] Access to the approved proxy succeeds.
- [ ] The proxy can reach an authorized public target and blocks unauthorized targets.
- [ ] Network isolation tests run automatically in CI or staging.
