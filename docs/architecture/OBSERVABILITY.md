# Kelvin Security Platform — Observability & Audit Architecture

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Active — Engineering Specification |
| **Milestone** | Phase 1 — Foundation & Core Architecture (`P1-19`) |
| **Related Docs** | `docs/architecture/decisions/ADR-0001.md` through `ADR-0003.md`, `docs/api/API_STANDARDS.md`, `docs/architecture/DATA_MODEL.md`, `docs/security/SECRETS.md` |
| **Owner** | Platform Engineering / Product Security |

---

## 1. Executive Summary & Principles

Kelvin maintains an architectural distinction between **operational debug logs** and **legal/compliance audit trails**:

1. **Operational Logs (Zap):**
   - Emitted as structured JSON in production (`go.uber.org/zap`).
   - Every log line contains the request `correlation_id` (propagated from `X-Correlation-ID`).
   - Automated redaction interceptors (`packages/common/logging`) strip passwords, API keys, tokens, session cookies, and Authorization headers.
   - Logs are ephemeral, rotatable, and stream to centralized log collectors (e.g., Datadog, CloudWatch, Loki).

2. **Compliance Audit Trail (`audit_log` Table):**
   - High-fidelity, immutable ledger stored in PostgreSQL (`audit_log` table per `docs/architecture/DATA_MODEL.md` §5.12).
   - Records who initiated a scan, what targets were inspected, scope additions/deletions, triage actions, and report exports.
   - **Append-Only:** Application database role (`kelvin_app`) has `INSERT` and `SELECT` permissions only; `UPDATE` and `DELETE` privileges are strictly revoked.
   - Retention floor of ≥ 24 months for regulatory and forensic compliance (SOC 2, ISO 27001, FedRAMP).

3. **Operational Metrics (Prometheus / OpenTelemetry):**
   - Standard metrics endpoint (`/metrics`) exposing request rates, error counters, active scanner jobs, and worker execution latencies.

---

## 2. Observability Architecture & Flow

```mermaid
flowchart TD
    Client["Client / Analyst Browser"] -->|HTTP Request with X-Correlation-ID| Gateway["API Gateway / Control Plane (apps/api)"]
    Gateway --> Middleware["Observability Middleware
• Correlation Context Injection
• Metrics Request Counter
• Status & Latency Recorder"]
    Middleware --> Redactor["Zap Redacting Core
• Regex & Key Filter
• Password / Bearer / Token Scrubbing"]
    Redactor --> AppLogs["Structured JSON Application Logs
(Stdout / Central Aggregator)"]
    
    Gateway --> AuditSvc["Audit Service (apps/api/internal/audit)"]
    AuditSvc -->|INSERT ONLY| AuditDB[("PostgreSQL audit_log Table
(Append-Only / Immutable)")]
    
    Gateway --> MetricsHandler["/metrics (Prometheus Format)"]
    MetricsHandler --> Prometheus["Prometheus / Datadog Scraper"]
```

---

## 3. Structured Logging Specification (Zap)

### 3.1 Standard JSON Format
In non-development environments (`KELVIN_ENV != development`), logs are emitted in single-line JSON format:

```json
{
  "level": "INFO",
  "ts": "2026-10-27T17:35:10.123Z",
  "caller": "middleware/accesslog.go:47",
  "msg": "request",
  "correlation_id": "c1f8a845-9f5b-4351-8d2a-431835bc4567",
  "method": "POST",
  "path": "/api/v1/assessments",
  "status": 201,
  "bytes": 542,
  "duration": "0.024s"
}
```

### 3.2 Context Propagation (`X-Correlation-ID`)
- Every HTTP request must be tagged with a correlation ID (UUIDv4/v7).
- If the incoming request has a valid `X-Correlation-ID` header, it is bound to `context.Context`.
- If missing or malformed, the middleware generates a new cryptographically secure UUID and echoes it in the response header.
- Every worker task payload enqueued in Redis inherits the `correlation_id` from the triggering API request.

### 3.3 Automated Secret Redaction Filter
The logging interceptor (`packages/common/logging/logging.go`) inspects:
- **Field Keys:** Any key matching `password`, `secret`, `token`, `api_key`, `jwt`, `private_key`, `auth`, `cookie`, `set-cookie`, `authorization` is substituted with `[REDACTED]`.
- **String Content:** Inline regex filters sanitize `Bearer <token>`, `Basic <credentials>`, and connection strings (`postgres://user:pass@host`).

---

## 4. Immutable Compliance Audit Trail

### 4.1 Schema Contract (`audit_log`)

| Column | Type | Nullable | Description |
| :--- | :--- | :--- | :--- |
| `id` | `uuid` | NO | Primary Key (UUIDv7 - insertion order = time order) |
| `tenant_id` | `uuid` | YES | Tenant scope (NULL for platform maintenance) |
| `actor_user_id` | `uuid` | YES | User ID snapshot (no FK to preserve history post-offboarding) |
| `actor_type` | `text` | NO | `USER`, `SERVICE`, `WORKER`, or `SYSTEM` |
| `action` | `text` | NO | Dotted action verb (e.g., `assessment.create`, `scope.update`) |
| `entity_type` | `text` | NO | Target entity (`assessment`, `asset`, `finding`, `report`) |
| `entity_id` | `uuid` | YES | Identifier of the affected entity |
| `payload` | `jsonb` | NO | Sanitized event diff and metadata; secrets never logged |
| `correlation_id` | `uuid` | NO | Cross-tier tracing identifier |
| `created_at` | `timestamptz` | NO | ISO8601 UTC timestamp, BRIN indexed |

### 4.2 Security & Privilege Enforcements (ADR-0002)
- Application database role (`kelvin_app`) has **only** `INSERT` and `SELECT` permissions on `audit_log`.
- `UPDATE` and `DELETE` commands are strictly blocked by database permissions.
- Archived to cold storage (WORM-compliant object storage) after 24 months.

---

## 5. Operational Metrics Baseline

Kelvin exposes Prometheus-compatible metrics on the control plane at `GET /metrics`:

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `kelvin_uptime_seconds` | Counter | Service uptime in seconds |
| `kelvin_http_requests_total` | Counter | Total HTTP requests handled |
| `kelvin_http_errors_total` | Counter | Total 5xx server error responses |
| `kelvin_jobs_active` | Gauge | Currently running or enqueued scanner jobs |
| `kelvin_jobs_completed_total` | Counter | Total scanner jobs completed successfully |
| `kelvin_jobs_failed_total` | Counter | Total scanner jobs failed or timed out |

