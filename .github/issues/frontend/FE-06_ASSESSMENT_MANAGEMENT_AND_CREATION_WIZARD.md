---
title: "FE-06 — Assessment Management & Creation Wizard"
labels: ["phase/frontend", "area/assessment", "kind/feature", "priority/critical", "status/ready-for-dev"]
milestone: "Frontend Development & Product Experience"
parent_issue: "FE-EPIC-01_DESIGN_AND_IMPLEMENT_COMPLETE_KELVIN_FRONTEND_APPLICATION.md"
workstream: "Frontend Application"
issue_id: "FE-06"
priority: "critical"
status: "ready-for-dev"
---

# FE-06 — Assessment Management & Creation Wizard

**Parent Epic:** [FE-EPIC-01: Complete KELVIN Frontend Application](FE-EPIC-01_DESIGN_AND_IMPLEMENT_COMPLETE_KELVIN_FRONTEND_APPLICATION.md) (Parent Epic #399)  
**Milestone:** [Frontend Development & Product Experience](../MILESTONE_FRONTEND.md)  
**Issue ID:** `FE-06`  
**Priority:** `critical`  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Build the assessment management catalog and a controlled 7-step assessment creation wizard enforcing authorized scope boundaries, profile selection, and duplicate prevention.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart LR
    subgraph Wizard ["7-Step Assessment Creation Wizard"]
        S1["Step 1: Select Authorized Target"] --> S2["Step 2: Choose Approved Scan Profile"]
        S2 --> S3["Step 3: Review Enabled Scanners (ZAP, Nuclei, TLS)"]
        S3 --> S4["Step 4: Configure Permitted Scan Options"]
        S4 --> S5["Step 5: Review Scope & Legal Authorization"]
        S5 --> S6["Step 6: Summary & Execution Parameters"]
        S6 --> S7["Step 7: Confirm & Dispatch Assessment"]
    end

    subgraph API ["Assessment API"]
        ValidateScope["POST /api/v1/assessments/validate-scope"]
        CreateJob["POST /api/v1/assessments (Idempotency Key)"]
    end

    S5 --> ValidateScope
    S7 --> CreateJob
    CreateJob -->|"201 Created (assessment_id)"| DetailView["Redirect to Assessment Detail Monitor"]
```

---

## 📋 Detailed Requirements

- Implement Assessment Catalog view displaying assessment ID, target, profile, trigger user, status badge, finding counts, duration, and actions.
- Implement comprehensive filtering (status, profile, date, target) and full-text search with pagination.
- Build 7-step Assessment Creation Wizard with linear step indicator and form validation at each step:
-   - Step 1: Target selector displaying only verified, authorized targets.
-   - Step 2: Assessment Profile selector (e.g. Web Baseline, Full Active, API Security) with descriptions.
-   - Step 3: Scanner capability inspection showing enabled tools (ZAP, Nuclei, HTTP Preflight, TLS).
-   - Step 4: Permitted options configuration (safe concurrency, custom headers, rate limits; no arbitrary shell injection).
-   - Step 5: Scope & Authorization confirmation requiring explicit checkbox acknowledgment.
-   - Step 6: Full summary review showing target, profile, timeout, and expected impact.
-   - Step 7: Final dispatch button with duplicate submission prevention via idempotency keys.
- Provide immediate cancellation and navigation back to catalog with confirmation prompt if form is dirty.

---

## 🛡️ Security & Architectural Invariants

- **Client-Side Data Integrity:** Form inputs must undergo strict validation before submission and reflect real backend states.
- **Sanitized Presentation:** All dynamic scanner results and evidence payloads must be sanitized to eliminate any XSS vulnerability risk.
- **Fail-Safe Error Boundaries:** Component crashes must be caught by React Error Boundaries without crashing the global application shell.
- **Responsive & Accessible:** Viewport reflow must support 320px to 1920px without horizontal scrollbars, complying with WCAG 2.2 Level AA.

---

## ✅ Acceptance Criteria

- [ ] Wizard prevents advancing to subsequent steps if required parameters are missing or invalid.
- [ ] Arbitrary shell commands or unsanitized flags cannot be submitted through the UI.
- [ ] Double-clicking submit button is prevented; duplicate submission returns existing job or blocks duplicate dispatch.
- [ ] Successful submission immediately transitions user to the live assessment execution monitor.

---

## 🔗 Related Documentation & Links

- Web Client Codebase: [`apps/web/`](../../../../apps/web/)
- Parent Milestone: [`MILESTONE_FRONTEND.md`](../MILESTONE_FRONTEND.md)
- Backend API Specification: [`docs/api/API_SPECIFICATION.md`](../../../../docs/api/API_SPECIFICATION.md)
