---
title: "EXEC-018 — Integrate Production OWASP ZAP Baseline Execution"
labels: ["kind/scanner-integration","backend","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-018"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 4 — Nuclei and ZAP Integration"
---

# EXEC-018 — Integrate Production OWASP ZAP Baseline Execution

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 4 — Nuclei and ZAP Integration  
**Issue ID:** `EXEC-018`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Complete production-ready ZAP baseline execution with report extraction and finding normalization.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Job["ZAP Job"] --> Container["Run Sandboxed ZAP Container"]
    Container --> Proxy["Route via Scoped Egress Proxy"]
    Proxy --> Baseline["Run zap-baseline.py"]
    Baseline --> Report["Extract /tmp/kelvin-zap-report.json"]
    Report --> Normalize["Normalize ZAP Alerts into Kelvin Findings"]
```

---

## 📋 Detailed Requirements

- Execute certified ZAP baseline scan under strict scoped egress.
- Keep active scanning disabled; extract structured report via safe mechanism.
- Normalize ZAP alerts preserving risk, confidence, evidence, and CWE.

---

## ✅ Acceptance Criteria

- [ ] ZAP baseline executes successfully.
- [ ] Active scanning remains disabled.
- [ ] Out-of-scope requests are blocked.
- [ ] Reports are captured and validated.
- [ ] ZAP output is normalized into Kelvin's result envelope.
- [ ] Timeout and cancellation work.
