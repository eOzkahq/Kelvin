---
title: "P3-34 — Implement Assessment History and Finding Observation Timeline"
labels: ["phase/3-findings", "workstream/e-remediation-history", "area/findings", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 3 — Findings Intelligence, Evidence & Reporting"
parent_issue: "../MILESTONE_PHASE_3.md"
workstream: "Workstream E — Assessment History & Remediation"
issue_id: "P3-34"
priority: "high"
status: "ready-for-dev"
---

# P3-34 — Implement Assessment History and Finding Observation Timeline

**Parent Epic:** [Phase 3 — Findings Intelligence, Evidence & Reporting](../MILESTONE_PHASE_3.md)  
**Milestone:** [Phase 3 — Findings Intelligence, Evidence & Reporting](../MILESTONE_PHASE_3.md)  
**Workstream:** Workstream E — Assessment History & Remediation  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Provide a reliable history of assessments and finding observations over time.

---

## 📐 Architecture & Workflow Diagram

```mermaid
flowchart TD
    Finding["Finding fnd_01J..."] --> HistoryService["Finding History Aggregator"]

    subgraph ObservationsTimeline ["Chronological Observations"]
        O1["Assessment #1 (2026-10-01) - Detected via ZAP Baseline"]
        O2["Assessment #2 (2026-10-15) - Detected via Nuclei"]
        O3["Assessment #3 (2026-11-01) - Scanner Not Executed (Scanner Skipped)"]
        O4["Assessment #4 (2026-11-15) - Re-tested: Still Present"]
    end

    HistoryService --> ObservationsTimeline
    ObservationsTimeline --> TimelineAPI["GET /api/v1/findings/{id}/observations"]
```

---

## 📋 Detailed Requirements

- Implement an assessment history retrieval service.
- Retrieve prior observations associated with a finding.
- Show when the finding was first observed and most recently observed.
- Preserve the assessment and scanner that produced each observation.
- Distinguish a missing finding from an assessment that did not execute the relevant scanner.
- Handle partial assessments accurately.
- Apply pagination and tenant authorization.
- Avoid interpreting absence of evidence as proof that an issue was resolved.

---

## 🛡️ Security & Architectural Invariants

- **Tenant Isolation:** All finding, observation, evidence, remediation, and report records must enforce strict tenant boundaries (`tenant_id = current_tenant_id()`, ADR-0002).
- **Data Integrity & Traceability:** Individual assessment observations and evidence records must remain immutable and never be overwritten by subsequent assessments.
- **Evidence Protection:** All sensitive credentials, tokens, session cookies, and authorization headers must be redacted before presentation and export (ADR-0005).
- **Explainability:** All calculated risk scores and priority rankings must be reproducible and mathematically explainable from documented input factors.

---

## ✅ Acceptance Criteria

- [ ] Authorized users can retrieve finding observation history.
- [ ] Each observation links to its originating assessment.
- [ ] Partial and incomplete assessments are distinguishable.
- [ ] Missing observations do not automatically imply resolution.
- [ ] Tests cover repeated and partial assessments.

---

## 🔗 Related Documentation & Links

- Findings Domain Architecture: [`docs/architecture/FINDINGS_DOMAIN.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Evidence Retention & Redaction: [`docs/security/EVIDENCE_LIFECYCLE.md`](../../../docs/security/ACCEPTABLE_USE.md)
- Risk Scoring Specification: [`docs/architecture/RISK_SCORING_MODEL.md`](../../../docs/architecture/SCAN_PROFILES.md)
- System Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
