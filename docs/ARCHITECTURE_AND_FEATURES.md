# Kelvin Security Platform — Features & Architectural Design

## 1. Executive Summary & Product Vision

**Kelvin** is an enterprise-grade, modular security assessment and vulnerability management platform designed for authorized security assessments. It provides a unified orchestration environment for asset management, target scope validation, modular scan execution, normalized findings analysis, and executive reporting.

The platform eliminates the fragmentation of running isolated command-line scanners by providing a centralized, policy-enforced control plane and sandboxed execution workers.

```mermaid
flowchart LR
    A[Target Assets & Scope] --> B[Kelvin Control Plane]
    B --> C[Policy & Scope Enforcement]
    C --> D[Sandboxed Worker Engine]
    D --> E[Normalized Findings Pipeline]
    E --> F[Evidence Store & Deduplication]
    F --> G[Interactive Dashboards & Reports]
```

---

## 2. Core Feature Matrix

### 2.1 Scope & Target Authorization Engine
* **Strict Scope Validation:** RFC 1918 / loopback / link-local prevention, DNS rebinding mitigations, and redirect destination enforcement.
* **Asset Ownership Verification:** DNS TXT record or HTTP challenge verification before aggressive scans.
* **Scan Profiles:** Low-impact passive discovery, standard automated assessment, and authorized deep assessment modes.

### 2.2 Modular Scanning & Orchestration
* **Vendor-Agnostic Worker Protocol:** Scanner engines communicate via isolated, standardized CLI/API wrappers.
* **Asynchronous Job Queues:** Distributed task queuing with prioritization, cancellation, heartbeats, and timeout management.
* **Process Isolation:** Worker sandboxing preventing compromised scan targets from executing arbitrary commands or SSRF against host services.

### 2.3 Unified Findings & Evidence Normalization
* **Canonical Vulnerability Schema:** Converts heterogeneous scanner outputs (e.g., OpenVAS, Nuclei, ZAP, Trivy) into standard vulnerability records.
* **Finding Deduplication & Fingerprinting:** Asset + Endpoint + Vulnerability Type fingerprinting to eliminate redundant alerts.
* **Evidence Preservation:** Encrypted storage of raw request/response payloads, screenshots, and proof-of-concept steps with automatic redaction of sensitive credentials.

### 2.4 Multi-Tenant Access & Role-Based Control (RBAC)
* **Tenant Isolation:** Row-level isolation ensuring zero leakage between distinct enterprise tenants or projects.
* **Granular Permissions:** Strict separation between Platform Admin, Security Analyst, and Read-Only Auditor roles.
* **Immutable Audit Trail:** Comprehensive recording of assessment initialization, approvals, target additions, and findings exports.

---

## 3. High-Level System Architecture

Kelvin follows an asynchronous, event-driven micro-modular architecture consisting of five primary tiers:
1. **Presentation Tier:** Single Page Application (SPA) dashboard for interactive review and orchestration.
2. **Control Plane (API Gateway & Core Service):** Enforces authentication, scope validation, persistence, and audit logging.
3. **Message & State Broker:** High-throughput task queue and publish-subscribe state coordinator.
4. **Sandboxed Worker Nodes:** Ephemeral worker containers running modular scan adapters.
5. **Data & Evidence Storage:** Relational database for core entities and object storage for raw evidence.

```mermaid
flowchart TD
    subgraph Client["Client Tier"]
        UI["Web Dashboard (React / Tailwind)"]
        CLI["Kelvin CLI Client"]
    end

    subgraph ControlPlane["Control Plane & API Layer"]
        Gateway["API Gateway & Reverse Proxy"]
        AuthService["Auth & RBAC Service"]
        ScopeEngine["Target & Scope Validator"]
        JobManager["Assessment Job Orchestrator"]
        FindingsService["Findings & Deduplication Service"]
    end

    subgraph MessageQueue["Async Message & Event Bus"]
        RedisQueue["Task Queue & Broker (Redis / BullMQ)"]
    end

    subgraph WorkerFleet["Sandboxed Scanner Worker Fleet"]
        Worker1["Worker Node A (Network & Discovery)"]
        Worker2["Worker Node B (Web Application)"]
        Worker3["Worker Node C (Configuration & Secrets)"]
    end

    subgraph DataStorage["Persistence & Evidence Tier"]
        Postgres[("Relational Database (PostgreSQL)")]
        ObjectStore[("Evidence & Blob Storage (MinIO / S3)")]
    end

    UI -->|HTTPS / WSS| Gateway
    CLI -->|REST API| Gateway
    Gateway --> AuthService
    Gateway --> ScopeEngine
    ScopeEngine --> JobManager
    JobManager --> Postgres
    JobManager --> RedisQueue
    RedisQueue --> WorkerFleet
    WorkerFleet -->|Raw Results| FindingsService
    FindingsService --> Postgres
    FindingsService --> ObjectStore
    Gateway --> FindingsService
```

---

## 4. Logical Data Flow: Scan Lifecycle

The lifecycle of an assessment from target submission to final report generation:

```mermaid
sequenceDiagram
    autonumber
    actor User as Security Analyst
    participant API as Kelvin Control Plane
    participant Scope as Scope Validator
    participant Queue as Job Queue
    participant Worker as Scan Worker
    participant DB as Persistence & Evidence
    
    User->>API: Create Assessment (Targets, Profile)
    API->>Scope: Validate Hostnames, IPs & Scope Policies
    alt Scope Invalid or Prohibited
        Scope-->>API: Reject with Scope Violation Error
        API-->>User: 422 Unprocessable Entity
    else Scope Approved
        Scope-->>API: Target Scope Validated
        API->>DB: Persist Assessment (Status: QUEUED)
        API->>Queue: Enqueue Scan Job with Execution Bounds
        API-->>User: Assessment Accepted (Job ID)
    end
    
    Queue->>Worker: Dispatch Job to Available Sandboxed Node
    Worker->>DB: Transition Job Status to RUNNING
    Worker->>Worker: Execute Sandboxed Tool Adapter
    Worker->>DB: Stream Normalized Findings & Evidence
    Worker->>Queue: Acknowledge Job Completion
    Queue->>DB: Transition Job Status to COMPLETED
    User->>API: Query Assessment Findings / Export Report
    API->>DB: Fetch Aggregated & Deduplicated Findings
    API-->>User: Render Interactive Dashboard / PDF Report
```

---

## 5. Security & Isolation Architecture

Because Kelvin handles potentially hostile target responses and sensitive assessment findings, the platform implements defense-in-depth principles:

```mermaid
flowchart TD
    subgraph External["External Network / Targets"]
        InternetTarget["Public Web / Network Target"]
    end

    subgraph DMZ["Scanner Sandboxing Layer"]
        Container["Rootless Container Worker"]
        EgressFilter["Strict Egress Proxy (Allow Target IPs Only)"]
        DNSResolver["Pinning DNS Resolver (Anti-Rebinding)"]
    end

    subgraph Internal["Kelvin Secure Internal Network"]
        APIServer["Kelvin API & DB"]
    end

    Container --> DNSResolver
    Container --> EgressFilter
    EgressFilter --> InternetTarget
    Container -.->|BLOCKED| Internal
    Container -->|One-Way Results Return| APIServer
```

1. **Anti-SSRF & Network Boundary:** Scan workers cannot route traffic back to internal infrastructure (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.1`, `169.254.169.254`).
2. **Ephemeral Containers:** Each assessment runs inside disposable, rootless container instances with bounded memory, CPU, and execution timeouts.
3. **Data Redaction:** Evidence ingestion pipelines strip authorization headers, cookies, API tokens, and private keys before persistence.
