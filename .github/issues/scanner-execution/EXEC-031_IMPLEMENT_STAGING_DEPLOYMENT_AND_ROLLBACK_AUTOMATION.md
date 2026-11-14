---
title: "EXEC-031 — Implement Staging Deployment and Rollback Automation"
labels: ["devops","infrastructure","priority/critical"]
milestone: "Scanner Execution Platform"
issue_id: "EXEC-031"
priority: "critical"
status: "ready-for-dev"
phase: "Phase 8 — Staging Certification and Deployment"
---

# EXEC-031 — Implement Staging Deployment and Rollback Automation

**Milestone:** Scanner Execution Platform (Milestone #10)  
**Phase:** Phase 8 — Staging Certification and Deployment  
**Issue ID:** `EXEC-031`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Create repeatable staging deployment and rollback procedure for worker and scanner images.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Deploy["Trigger Deploy"] --> Verify["Verify Release Manifest & Digests"]
    Verify --> Pull["Pull ARM64 Images"]
    Pull --> Check["Validate Config & CA Certs"]
    Check --> Start["Start Worker (--profile worker)"]
    Start --> Health{"Readiness Check"}
    Health -->|Pass| Done["Deployment Certified"]
    Health -->|Fail| Rollback["Rollback to Known-Good Worker"]
```

---

## 📋 Detailed Requirements

- Verify manifests, signatures, and ARM64 architecture before starting worker.
- Automate smoke testing and health verification upon deployment.
- Support clean rollback to prior stable version on failure.

---

## ✅ Acceptance Criteria

- [ ] Deployment is repeatable.
- [ ] Previous working API remains unaffected.
- [ ] Scanner worker is not activated before verification.
- [ ] Rollback restores the previous worker version.
- [ ] Deployment evidence is retained.
