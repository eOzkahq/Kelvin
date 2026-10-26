# Kelvin MVP Definition & Phase Bifurcation Framework

## 1. Product Scope Bifurcation

To guarantee rapid validation, operational reliability, and architectural purity, Kelvin explicitly bifurcates product capabilities into three distinct categories: **MVP Core Scope**, **Post-MVP Growth Scope**, and **Strict Non-Goals**.

```mermaid
flowchart TD
    subgraph InScopeMVP["MVP Scope (Phase 1 & Phase 2 Baseline)"]
        A1["Scope & Policy Enforcement"]
        A2["Asynchronous Job Lifecycle Engine"]
        A3["Single-Tenant Local Lab & Worker Sandbox"]
        A4["Canonical Finding Schema Normalization"]
        A5["Basic HTML/JSON Report Export"]
    end

    subgraph FutureScope["Post-MVP Scope (Phases 3 — 6)"]
        B1["Multi-Tenant Isolation & SAML/SSO"]
        B2["Distributed Cloud Worker Clusters"]
        B3["Continuous Attack Surface Monitoring"]
        B4["AI-Guided Vulnerability Prioritization"]
        B5["Jira / GitHub Issues Bidirectional Sync"]
    end

    subgraph NonGoals["Strict Non-Goals (Excluded Out of Scope)"]
        C1["Unconstrained Arbitrary Port Flooding / DDoS"]
        C2["Unauthenticated Public Scanning Service"]
        C3["Automatic Exploitation / Payload Dropping"]
        C4["Commercial Antivirus Replacement"]
    end

    InScopeMVP -->|Evolutionary Progression| FutureScope
```

---

## 2. Core Domain Data Model (MVP ERD)

The relational schema strictly isolates assessment definitions, target scoping, execution jobs, and discovered findings:

```mermaid
erDiagram
    TENANT ||--o{ USER : contains
    TENANT ||--o{ PROJECT : owns
    PROJECT ||--o{ ASSET : tracks
    PROJECT ||--o{ ASSESSMENT : schedules
    ASSESSMENT ||--o{ JOB : dispatches
    JOB ||--o{ FINDING : produces
    FINDING ||--o{ EVIDENCE : attaches
    ASSESSMENT ||--o{ REPORT : compiles

    TENANT {
        uuid id PK
        string name
        string slug
        timestamp created_at
    }

    USER {
        uuid id PK
        uuid tenant_id FK
        string email
        string password_hash
        string role
        boolean is_active
    }

    PROJECT {
        uuid id PK
        uuid tenant_id FK
        string name
        string description
        jsonb scope_boundaries
    }

    ASSET {
        uuid id PK
        uuid project_id FK
        string target_type
        string value
        boolean is_verified
    }

    ASSESSMENT {
        uuid id PK
        uuid project_id FK
        string profile_name
        string status
        timestamp scheduled_at
    }

    JOB {
        uuid id PK
        uuid assessment_id FK
        string worker_id
        string status
        integer exit_code
        timestamp started_at
        timestamp finished_at
    }

    FINDING {
        uuid id PK
        uuid job_id FK
        string fingerprint
        string title
        string severity
        float confidence
        string cwe_id
        string affected_target
    }

    EVIDENCE {
        uuid id PK
        uuid finding_id FK
        string evidence_type
        text raw_payload_redacted
        string blob_storage_url
    }

    REPORT {
        uuid id PK
        uuid assessment_id FK
        string format
        string download_url
        timestamp generated_at
    }
```

---

## 3. Assessment Job State Machine

To prevent deadlocks, race conditions, or unmonitored failures, every assessment job conforms to the following deterministic state transition graph:

```mermaid
stateDiagram-v2
    [*] --> Queued : Analyst Triggers Assessment
    Queued --> ValidatingScope : Worker Picks Job
    
    ValidatingScope --> Running : Target Scope Approved
    ValidatingScope --> Failed : Scope Violation / Prohibited IP
    
    Running --> Completed : All Checks Finished Gracefully
    Running --> TimedOut : Exceeded Profile Execution Budget
    Running --> Cancelled : User Aborts Assessment
    Running --> Failed : Worker Crash / Adapter Error
    
    TimedOut --> [*]
    Cancelled --> [*]
    Failed --> [*]
    Completed --> GeneratingReport : Auto-Trigger Report
    GeneratingReport --> [*]
```

---

## 4. Phase-by-Phase Bifurcation & Delivery Criteria

### Phase 1: Foundation & Core Architecture (Current Milestone — 25 Issues)
* **Objective:** Establish unassailable security boundaries, target validation engine, async job state machine, clean repository scaffolding, database persistence, and developer environment.
* **Delivery Artifacts:**
  - `docs/PRODUCT_VISION.md`, `docs/security/THREAT_MODEL.md`, `docs/architecture/`
  - Scope validation engine with strict anti-SSRF and DNS rebinding protections
  - PostgreSQL schema migrations + Redis background job queue abstraction
  - Unified finding and evidence normalized schema contracts
  - 25 tracked foundational GitHub issues

### Phase 2: Engine Integration & Sandboxing
* **Objective:** Containerized execution daemon, pluggable scanner adapter protocol, initial scanners (port/network discovery + web baseline).
* **Delivery Artifacts:**
  - Rootless Docker worker sandbox with locked egress rules
  - Adapter protocol for CLI/JSON vulnerability scanners
  - Real-time job status streaming over WebSocket

### Phase 3: Finding Normalization, Deduplication & Reporting
* **Objective:** Automated deduplication, severity prioritization, credential redaction, and exportable PDF/JSON reports.
* **Delivery Artifacts:**
  - Canonical vulnerability ingestion engine
  - Sensitive token/cookie redaction pipeline
  - Customizable executive and technical assessment reports

### Phase 4: Enterprise Identity & Multi-Tenancy
* **Objective:** Complete organization separation, SAML 2.0 / OIDC integrations, fine-grained access control, and compliance-grade audit logging.
* **Delivery Artifacts:**
  - Row-level database security policies
  - Audit log exporter for SIEM ingestion
  - Enterprise SSO connectors

### Phase 5 & 6: Continuous Automation & Ecosystem Extensibility
* **Objective:** Scheduled recurrence, attack surface diffing, third-party plugin developer SDK, and heuristic risk analysis.
