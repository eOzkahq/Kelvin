---
title: "P3-31 — Implement Authorized Evidence Retrieval and Access Controls"
labels: ["phase/3-findings", "workstream/d-evidence-management", "area/api", "kind/feature", "priority/high", "status/ready-for-dev"]
milestone: "Phase 3 — Findings Intelligence, Evidence & Reporting"
parent_issue: "../MILESTONE_PHASE_3.md"
workstream: "Workstream D — Evidence Management"
issue_id: "P3-31"
priority: "high"
status: "ready-for-dev"
---

# P3-31 — Implement Authorized Evidence Retrieval and Access Controls

**Parent Epic:** [Phase 3 — Findings Intelligence, Evidence & Reporting](../MILESTONE_PHASE_3.md)  
**Milestone:** [Phase 3 — Findings Intelligence, Evidence & Reporting](../MILESTONE_PHASE_3.md)  
**Workstream:** Workstream D — Evidence Management  
**Status:** `ready-for-dev`  

---

## 🎯 Purpose

Allow authorized users to access relevant evidence while preventing unauthorized disclosure.

---

## 📐 Architecture & Workflow Diagram

```mermaid
sequenceDiagram
    participant User as Analyst / Client
    participant API as Evidence API Gateway
    participant AuthZ as Tenant & Scope Authorizer
    participant Store as Secure Storage Backend

    User->>API: GET /findings/{f_id}/evidence/{e_id}/download
    API->>AuthZ: Authorize(User, TenantID, FindingID, EvidenceID)
    AuthZ-->>API: Authorized
    API->>Store: GenerateShortLivedToken(e_id, ttl=300s)
    Store-->>API: Ephemeral Delivery Token / Pre-signed URL
    API-->>User: 200 OK { download_url, expires_in: 300 }
```

---

## 📋 Detailed Requirements

- Implement evidence metadata and content retrieval operations (GET /api/v1/findings/{id}/evidence/{evidence_id}).
- Enforce tenant and finding-level authorization.
- Check permissions before issuing access to an evidence object.
- Use short-lived access mechanisms (e.g. 5-minute pre-signed URLs or streaming auth tokens).
- Prevent predictable object identifiers from enabling access.
- Avoid exposing storage-provider credentials or internal bucket paths.
- Support evidence preview or download only for approved content types.
- Set safe response headers (Content-Disposition, X-Content-Type-Options: nosniff).
- Record access decisions where required.

---

## 🛡️ Security & Architectural Invariants

- **Tenant Isolation:** All finding, observation, evidence, remediation, and report records must enforce strict tenant boundaries (`tenant_id = current_tenant_id()`, ADR-0002).
- **Data Integrity & Traceability:** Individual assessment observations and evidence records must remain immutable and never be overwritten by subsequent assessments.
- **Evidence Protection:** All sensitive credentials, tokens, session cookies, and authorization headers must be redacted before presentation and export (ADR-0005).
- **Explainability:** All calculated risk scores and priority rankings must be reproducible and mathematically explainable from documented input factors.

---

## ✅ Acceptance Criteria

- [ ] Authorized users can retrieve permitted evidence.
- [ ] Unauthorized users cannot access evidence by guessing identifiers.
- [ ] Storage credentials and internal paths remain private.
- [ ] Download and preview behavior is restricted to approved file types.
- [ ] Security tests cover cross-tenant and direct-object-access attempts.

---

## 🔗 Related Documentation & Links

- Findings Domain Architecture: [`docs/architecture/FINDINGS_DOMAIN.md`](../../../docs/architecture/FINDING_SCHEMA.md)
- Evidence Retention & Redaction: [`docs/security/EVIDENCE_LIFECYCLE.md`](../../../docs/security/ACCEPTABLE_USE.md)
- Risk Scoring Specification: [`docs/architecture/RISK_SCORING_MODEL.md`](../../../docs/architecture/SCAN_PROFILES.md)
- System Architecture Baseline: [`docs/architecture/SYSTEM_ARCHITECTURE.md`](../../../docs/architecture/SYSTEM_ARCHITECTURE.md)
