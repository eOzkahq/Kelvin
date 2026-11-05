# ADR-0006: Redis & Supabase Infrastructure Integration

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Accepted |
| **Date** | 2026-11-05 |
| **Author** | Platform Infrastructure & Architecture Engineering |
| **Planning Reference** | INFRA-01 |
| **Supersedes** | None |
| **Superseded by** | None |
| **Reviewers** | Platform Engineering, Product Security, Cloud Operations |
| **Classification** | Internal — Engineering Record |

---

## 1. Context & Problem Statement

KELVIN requires an enterprise-grade cloud and distributed execution substrate to support high-throughput asynchronous security assessments, authoritative data persistence, distributed worker orchestration, low-latency caching, and private evidence storage.

Prior implementations relied on local PostgreSQL instances and embryonic queue abstractions without:
1. Unified production connection pooling and TLS enforcement compatible with Supabase Managed PostgreSQL.
2. Production-grade Redis 7+ clustering, distributed lease locking with heartbeat renewals, and automated Dead-Letter Queue (DLQ) routing for poison-pill tasks.
3. Secure, private object storage with time-limited cryptographic signed URLs for technical reports and sanitized scanner evidence.
4. Guaranteed dual-write consistency between PostgreSQL authoritative states (`QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`) and Redis broker events.

---

## 2. Decision Drivers

- **Audit-First Principle:** Preserve all 45 existing PostgreSQL migrations (`000001_` to `000045_`), domain models, and RLS policies.
- **Authoritative Separation:** PostgreSQL remains the single source of truth for all business entities, assessment state, findings, and immutable audit logs. Redis is strictly ephemeral and coordination-focused.
- **Queue Reliability & Poison-Pill Defenses:** Enforce deterministic idempotency keys, exponential backoff with jitter (max 3 retries), and DLQ quarantine.
- **Distributed Concurrency:** Distributed worker lease locks with heartbeat extensions prevent split-brain dual-worker scanning.
- **Object Storage Security:** Private buckets (`kelvin-reports-private`, `kelvin-evidence-private`) with signed URL access expiring in $\le 300$ seconds. Zero public access.
- **Tenant Isolation:** Mathematical and functional isolation across database (tenant_id foreign keys & RLS), cache (namespaced `kelvin:{tenant_id}:{resource}:{id}`), and storage (`{tenant_id}/{assessment_id}/{file_id}`).

---

## 3. Decision

1. **Redis 7+ Integration:**
   - Use `github.com/redis/go-redis/v9` with robust connection pooling (`REDIS_POOL_SIZE`, `REDIS_MIN_IDLE_CONNS`), timeouts, keepalives, and optional TLS.
   - Implement priority assessment queuing on Redis Streams.
   - Enforce idempotency using `SETNX` with TTL.
   - Implement exponential retry policies routing persistent failures to Dead-Letter Queues.
   - Implement atomic lease locking (`AcquireLease`, `RenewLease`, `ReleaseLease`) using Redis primitives and Lua scripts.
   - Enforce tenant-scoped cache key formatting.

2. **Supabase PostgreSQL Integration:**
   - Connect via `pgxpool` with TLS encryption (`sslmode=verify-full`).
   - Retain full compatibility with `golang-migrate` runner.
   - Tune connection pools for Supabase Transaction Pooler (PgBouncer) and direct connections.
   - Provide `/health/db` readiness probes.

3. **Supabase Storage Integration:**
   - Abstract object storage behind Go `StorageService` interface (`Upload`, `Download`, `GetSignedURL`, `Delete`).
   - Implement Supabase Storage provider with HMAC-SHA256 signed URL generation (300s TTL).
   - Validate MIME types, magic bytes, and 50MB file size limits.
   - Reject cross-tenant retrieval.

---

## 4. Consequences & Invariants

- **Positive:** Production scalability, resilient worker recovery, zero data loss upon worker crash, strict compliance with SOC 2 and ISO 27001 data isolation.
- **Negative:** Requires external managed Redis and Supabase infrastructure; requires local emulation via Docker Compose for offline development.
- **Invariant:** Secrets (`SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_DB_PASSWORD`, `REDIS_PASSWORD`) must never be exposed to frontend code or client bundles.
