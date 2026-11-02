# KELVIN Production Data Services Hardening Specification

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Approved — Production Engineering Specification |
| **Milestone** | Phase 5 — Production Hardening, Deployment & Release (`P5-05`) |
| **Parent Roadmap** | [KELVIN Engineering Roadmap](../ISSUE-02_ENGINEERING_ROADMAP.md) |
| **Parent Issue** | Issue #361 (`P5-05`) |
| **Architecture Reference** | [`docs/architecture/PRODUCTION_DEPLOYMENT_ARCHITECTURE.md`](../architecture/PRODUCTION_DEPLOYMENT_ARCHITECTURE.md) |
| **Review Cadence** | Quarterly |
| **Classification** | Internal — Enterprise Engineering Baseline |

---

## 1. Overview & Data Security Architecture

KELVIN isolates and hardens its three core production persistence services:
1. **Relational Persistence (PostgreSQL 16 Multi-AZ):** Tenant data, scan metadata, findings, observations, audit logs.
2. **Task Queue & Message Broker (Redis 7.2 / Valkey HA):** Ephemeral task dispatch, heartbeats, distributed concurrency locks.
3. **Evidence & Report Object Storage (AWS S3 / MinIO):** Raw scanner outputs, HTTP request/response payloads, compliance PDF/JSON exports.

```mermaid
flowchart TD
    subgraph AppZone ["Zone 1: Application Control Plane"]
        API["Go API Services"]
        PgBouncer["PgBouncer Pooler (Transaction Mode, Port 6432)"]
    end

    subgraph WorkerZone ["Zone 2: Asynchronous Worker Fleet"]
        Worker["Worker Runner Fleet"]
    end

    subgraph DataZone ["Zone 4: Isolated Data Tier"]
        subgraph PostgresTier ["PostgreSQL 16 Multi-AZ"]
            PrimaryDB["Primary Instance (SCRAM-SHA-256)"]
            ReplicaDB["Multi-AZ Sync Replica"]
        end

        subgraph BrokerTier ["Redis 7.2 / Valkey HA"]
            RedisPrimary["Primary Redis Node (noeviction, TLS)"]
            RedisReplica["Sentinel Replicas"]
        end

        subgraph StorageTier ["Encrypted S3 Storage"]
            EvidenceBucket["Evidence Bucket (KMS-SSE, 90d Glacier, 365d Expiry)"]
            ReportsBucket["Reports Bucket (KMS-SSE, 90d Glacier, 365d Expiry)"]
        end
    end

    API -->|Port 6432| PgBouncer
    PgBouncer -->|Port 5432 (SSL verify-full)| PrimaryDB
    PrimaryDB -.->|Sync WAL Streaming| ReplicaDB

    API -->|Task Publish (TLS + AUTH)| RedisPrimary
    Worker -->|Task Consume (Atomic Lease)| RedisPrimary
    RedisPrimary -.-> RedisReplica

    API -->|Generate Presigned S3 URLs| StorageTier
    Worker -->|Upload Normalized Artifacts| StorageTier
```

---

## 2. Database Role Segregation & Least Privilege

KELVIN establishes three separate database identities to eliminate the risk of runtime schema manipulation or privilege escalation:

| Role Name | Scope of Permissions | Used By | Enforced Timeouts |
| :--- | :--- | :--- | :--- |
| **`kelvin_migrator`** | DDL (CREATE, ALTER, DROP), Schema migrations, Index creation | CI/CD deployment pipeline runner | `statement_timeout = 300s` |
| **`kelvin_app`** | DML only (SELECT, INSERT, UPDATE, DELETE). **Zero DDL rights.** | Go API and Background Worker processes | `statement_timeout = 30s`<br>`idle_in_transaction_timeout = 60s`<br>`lock_timeout = 10s` |
| **`kelvin_auditor`** | Read-Only (SELECT only). | Security compliance and audit export tools | `statement_timeout = 60s` |

---

## 3. Connection Pooling & Resource Limits (PgBouncer)

- **Mode:** `transaction` mode connection pooling. Sessions are recycled after every transaction, preventing connection starvation and unbounded thread proliferation.
- **Client Capacity:** `max_client_conn = 2000` client connections fronting an active pool of `default_pool_size = 80` backend PostgreSQL connections.
- **Session Reset:** `server_reset_query = DISCARD ALL` prevents leakage of temporary tables or session variables across clients.
- **Encryption:** Enforces TLS encryption for all incoming client connections and `server_tls_sslmode = verify-full` for all backend RDS connections.

---

## 4. Queue Durability & Task Protection (Redis / Valkey)

1. **Eviction Policy:**
   - Explicitly configured with `maxmemory-policy: noeviction`. If memory thresholds are reached, Redis returns an error rather than silently evicting uncompleted assessment tasks.
2. **Persistence & Fsync:**
   - Append-Only File (AOF) with `everysec` synchronization.
3. **Task Leases & Watchdog:**
   - Assessment tasks are leased using atomic consumer group claims. If a worker pod crashes, the lease expires after 60 seconds and is safely claimed by a healthy peer worker.

---

## 5. Storage Encryption & Access Controls

- **Encryption at Rest:** All evidence and report S3 objects are encrypted with a Customer-Managed Key (CMK) via AWS KMS (`aws:kms`).
- **Network Boundaries:** Direct access to S3 from application and worker instances is routed exclusively via an AWS S3 VPC Gateway Endpoint, eliminating exposure to the public internet.
- **Public Access Prevention:** AWS S3 Block Public Access is strictly enabled (`block_public_acls = true`, `block_public_policy = true`).

---

## 6. Bounded Retries & Failure Circuit Breakers

To avoid catastrophic cascading retry storms during database or cache interruptions:
- **Connection Backoff:** Exponential backoff with full jitter: $t_{wait} = \min(t_{max}, t_{base} \times 2^{\text{attempt}}) \times \text{rand}(0, 1)$.
- **Retry Cap:** Maximum of 3 retries before failing fast and returning structured 503 Service Unavailable errors to upstream clients.
