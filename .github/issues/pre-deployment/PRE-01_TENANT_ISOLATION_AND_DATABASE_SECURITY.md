---
title: "PRE-01 — Tenant Isolation and Database Security"
labels: ["area/database", "kind/security", "priority/critical", "status/completed", "production-readiness"]
milestone: "Pre-Deployment Production Hardening"
parent_issue: "PRE-DEPLOY-EPIC_KELVIN_PRE_DEPLOYMENT_ENGINEERING_HARDENING.md"
workstream: "Pre-Deployment Hardening"
issue_id: "PRE-01"
priority: "critical"
status: "completed"
---

# PRE-01 — Tenant Isolation and Database Security

**Parent Epic:** [PRE-DEPLOY-EPIC: KELVIN Pre-Deployment Engineering Hardening](PRE-DEPLOY-EPIC_KELVIN_PRE_DEPLOYMENT_ENGINEERING_HARDENING.md) (Parent Epic #464)  
**Milestone:** [Pre-Deployment Production Hardening](../MILESTONE_PRE_DEPLOYMENT.md)  
**Issue ID:** `PRE-01`  
**Priority:** `critical` (Deployment-blocking)  
**Status:** `completed`  
**Target Pull Request:** `fix(db): standardize tenant rls and job store isolation`  

---

## 🎯 Purpose

Standardize PostgreSQL tenant context settings, enforce transaction-scoped tenant boundaries across all repositories, apply FORCE ROW LEVEL SECURITY, and fix job-store cross-tenant access vulnerabilities.

---

## 📐 Architecture & Workflow Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Client as API Request / User Context
    participant Repo as Go Database Repository
    participant DB as Supabase PostgreSQL Pool
    participant RLS as PostgreSQL RLS Engine

    Client->>Repo: Execute Tenant Operation (tenant_id = 'T1')
    Repo->>DB: BEGIN Transaction
    Repo->>DB: SELECT set_config('app.current_tenant_id', 'T1', true); SET ROLE kelvin_app;
    Repo->>DB: SELECT * FROM findings WHERE id = 'F1';
    DB->>RLS: Evaluate Policy: tenant_id = current_tenant_id()
    alt Record belongs to T1
        RLS-->>DB: Policy Matched
        DB-->>Repo: Return Finding Record
        Repo->>DB: COMMIT Transaction
    else Record belongs to T2 (Attack Attempt)
        RLS-->>DB: Zero Rows / Access Denied
        DB-->>Repo: Record Not Found
        Repo->>DB: ROLLBACK Transaction
        Repo-->>Client: 404 Not Found / 403 Forbidden
    end
```

---

## 📋 Detailed Requirements

- Standardize tenant context setting: resolve conflict between app.tenant_id and app.current_tenant_id by establishing current_tenant_id() as the single canonical SQL helper.
- Enforce tenant context on all database operations: all tenant-scoped queries must run inside a transaction setting the tenant ID and assuming kelvin_app role.
- Audit and enforce RLS: ensure ROW LEVEL SECURITY and FORCE ROW LEVEL SECURITY are active on all tenant tables, preventing bypass even by table owners.
- Fix job-store scoping in apps/api/pkg/job/state.go: require tenant ID verification on job updates instead of querying by job ID alone.
- Implement authorized service path for worker job claiming across tenants without disabling or bypassing database RLS.
- Add automated security tests verifying cross-tenant read/update denial and fail-closed behavior when tenant context is missing.

---

## 🛡️ Security & Architectural Invariants

- **Mandatory Fail-Closed:** Any missing security context, tenant identifier, or cryptographic key must fail closed and refuse execution.
- **Strict Tenant Scoping:** All operations must resolve tenant context through canonical `current_tenant_id()` with RLS enforced.
- **Zero Insecure Fallbacks:** Remove all production fallback mechanisms that weaken security (e.g. `sslmode=disable`, hardcoded signing keys, nil repositories).
- **Resource Limits & Least Privilege:** Containers and database pools must be bounded to protect the 1 OCPU / 6 GB Oracle environment.

---

## ✅ Acceptance Criteria

- [x] Tenant A cannot read, query, or mutate Tenant B's targets, assessments, findings, or evidence.
- [x] Database queries without an established tenant context immediately fail closed.
- [x] Job updates scoped only by job ID are eliminated; all client queries enforce tenant boundaries.
- [x] Automated integration tests verify RLS enforcement under actual kelvin_app database credentials.

---

## 🔗 Related Documentation & Links

- Parent Pre-Deployment Epic: [`PRE-DEPLOY-EPIC_KELVIN_PRE_DEPLOYMENT_ENGINEERING_HARDENING.md`](PRE-DEPLOY-EPIC_KELVIN_PRE_DEPLOYMENT_ENGINEERING_HARDENING.md)
- Control Plane API: [`apps/api/`](../../../../apps/api/)
- Worker Runtime: [`apps/worker/`](../../../../apps/worker/)
- Deployment Guides: [`docs/deployment/`](../../../../docs/deployment/)
