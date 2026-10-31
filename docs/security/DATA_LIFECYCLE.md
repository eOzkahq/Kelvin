# Kelvin — Data Lifecycle & Evidence Retention

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Baseline — Peer Review Required (Security review mandatory) |
| **Milestone** | Phase 1 — Foundation & Core Architecture (`P1-32`) |
| **Depends On** | `docs/security/SECRETS.md` (`P1-15`), `docs/architecture/DATA_MODEL.md` (`P1-10`), `docs/security/RBAC_MATRIX.md` (`P1-12`), `docs/security/SECURITY_TESTING.md` (`P1-27`) |
| **Owner** | Product Security / Platform Engineering |
| **Classification** | Internal — Engineering Specification (Security-Critical) |

---

## 1. Executive Summary

Security assessments routinely capture sensitive information: HTTP request/response
headers, URLs, configuration details, screenshots, logs, request/response samples,
session cookies, authentication tokens, and exported reports. Retaining this
information indefinitely or exposing it through logs and artifacts dramatically
increases the consequences of a data breach.

This document defines Kelvin's consistent lifecycle policy for assessment evidence
and related security data: classification by sensitivity tiers, automated redaction
before persistence, configurable tenant-level retention with automated deletion
sweeps, and secure cryptographic erasure with signed URL access controls.

---

## 2. Data Sensitivity Classification

Assessment data is classified into three sensitivity tiers. Every piece of
evidence, finding, report, or artifact is assigned a tier at ingestion time.

### Tier 1 — Public / Non-Sensitive

| Data | Examples | Retention | Access |
| :--- | :--- | :--- | :--- |
| Scan metadata | Assessment ID, job ID, target hostname, scan profile, status | Per tenant retention (default 90 days active) | Tenant-scoped, authenticated |
| Finding summaries | Vulnerability title, severity, CVSS score, remediation guidance | Per tenant retention (default 365 days archived) | Tenant-scoped, authenticated |

### Tier 2 — Confidential

| Data | Examples | Retention | Access |
| :--- | :--- | :--- | :--- |
| HTTP request headers (sanitized) | Headers with auth/cookie tokens redacted | 90 days active, then archived | Tenant-scoped, signed URL |
| HTTP response headers (sanitized) | Headers with session/set-cookie redacted | 90 days active, then archived | Tenant-scoped, signed URL |
| Evidence previews | Redacted request/response bodies (≤ 64 KiB) | 90 days active, then archived | Tenant-scoped, signed URL |
| Screenshots | Redacted screen captures | 90 days active, then archived | Tenant-scoped, signed URL |

### Tier 3 — Restricted / Secret

| Data | Examples | Retention | Access |
| :--- | :--- | :--- | :--- |
| Raw credentials | Bearer tokens, session IDs, API keys, passwords | **Never stored**; redacted at ingestion | N/A |
| Raw HTTP bodies with secrets | Unredacted request/response containing credentials | **Never stored**; redacted at ingestion | N/A |
| Private keys / certificates | TLS private keys, signing keys | **Never stored**; redacted at ingestion | N/A |
| Cloud metadata responses | AWS/GCP/Azure instance metadata (169.254.169.254) | **Blocked**; never reaches storage | N/A |

**Rule:** Tier 3 data must never be persisted. If a scanner returns Tier 3 data,
the redaction engine must strip it before the evidence reaches the artifact store.
Any Tier 3 data that cannot be reliably redacted causes the finding/evidence to be
rejected.

---

## 3. Retention Periods

Retention is configurable per tenant via the `retention` configuration block.
Defaults:

| Classification | Active (signed URL access) | Archived (cold storage) | Secure Purge (cryptographic erasure) |
| :--- | :--- | :--- | :--- |
| Tier 1 — Public / Non-Sensitive | 90 days | 270 days (total 365) | 365 days |
| Tier 2 — Confidential | 90 days | 270 days (total 365) | 365 days |
| Tier 3 — Restricted / Secret | N/A (never stored) | N/A | N/A (immediate redaction) |

Retention sweep runs every 24 hours (configurable) and:

1. Marks evidence older than the active period as `archived` (signed URLs still
   work but with a shorter TTL).
2. Permanently purges evidence older than the total retention period:
   - Database rows are soft-deleted (`deleted_at` set), then hard-deleted after
     a grace period.
   - Object store binaries are cryptographically erased (overwritten with random
     data) then deleted.
   - Audit log entry written for every purge.

---

## 4. Redaction Rules

The automated redaction engine runs at ingestion time, before any evidence is
persisted to the database or object store. It applies pattern-based and
schema-aware redaction:

| Rule ID | Pattern | Replacement | Description |
| :--- | :--- | :--- | :--- |
| R1 | `Authorization: Bearer <token>` | `Authorization: Bearer [REDACTED]` | Strip bearer tokens |
| R2 | `Authorization: Basic <token>` | `Authorization: Basic [REDACTED]` | Strip basic auth |
| R3 | `Set-Cookie: <name>=<value>; ...` | `Set-Cookie: <name>=[REDACTED]; ...` | Mask session cookies |
| R4 | `Cookie: <name>=<value>; ...` | `Cookie: <name>=[REDACTED]; ...` | Mask request cookies |
| R5 | `password=...` / `pass=...` / `pwd=...` | `<field>=[REDACTED]` | Redact password form fields |
| R6 | `secret=...` / `api_key=...` / `token=...` | `<field>=[REDACTED]` | Redact secret/token fields |
| R7 | `authorization: ...` (header) | `authorization: [REDACTED]` | Redact authorization header value |
| R8 | JWT pattern (`eyJ...eyJ...eyJ...`) | `[REDACTED_JWT]` | Redact JWT tokens anywhere |
| R9 | AWS secret key pattern | `[REDACTED_AWS_KEY]` | Redact AWS secret access keys |
| R10 | Private key blocks (`-----BEGIN ... PRIVATE KEY-----`) | `[REDACTED_PRIVATE_KEY]` | Redact PEM private keys |

Redaction is **lossy by design**: the original unredacted data is never stored.
If a consumer needs unredacted evidence, they must re-run the scan against the
target with appropriate authorization.

---

## 5. Signed URL Access

Evidence artifacts (Tier 2 confidential data) are never served directly by object
key. Access is mediated through short-lived, HMAC-signed URLs:

| Property | Requirement |
| :--- | :--- |
| Signing algorithm | HMAC-SHA256 with tenant-scoped key |
| URL format | `/api/v1/evidence/{evidence_id}/download?signature={hmac}&expires={unix_ts}` |
| Default TTL | 15 minutes (configurable, max 24 hours) |
| Authorization | Tenant-scoped; signature binds evidence ID + tenant ID + expiry |
| Revocation | Evidence soft-delete invalidates all outstanding signed URLs |
| Audit | Every signed URL generation and validation is logged with correlation ID |

Signed URL format:

```
/api/v1/evidence/{evidence_id}/download
  ?expires=<unix_timestamp>
  &signature=hmac_sha256(signing_key, "{evidence_id}|{tenant_id}|{expires}")
```

---

## 6. Secure Erasure

When evidence reaches its purge deadline:

1. **Database:** Soft-delete row (`deleted_at` timestamp). After a 7-day grace
   period, hard-delete the row.
2. **Object Store:** Overwrite the binary with cryptographically random data
   (same length as original), then issue a `DELETE` object store API call.
3. **Audit:** Write an `evidence.purged` audit event with evidence ID, tenant ID,
   purged-by principal, and timestamp.

If object store deletion fails, the sweep retries with exponential backoff up to
3 times. Persistent failures generate a `evidence.purge_failed` alert.

---

## 7. Automated Retention Sweep

A background worker task runs on a configurable interval (default 24h):

1. Queries the database for evidence records whose `created_at` + retention
   period has passed.
2. For each expired record:
   a. Transitions `active` → `archived` (if within archive window).
   b. Transitions `archived` → `purging` and initiates secure erasure.
   c. On successful erasure, marks `purged`; on failure, marks `purge_failed`
      and schedules retry.
3. Logs summary metrics: records scanned, archived, purged, failed.

The sweep is safe to run concurrently from multiple control-plane instances
(uses `FOR UPDATE SKIP LOCKED` row locking, same pattern as `Store.ReapStalled`).

---

## 8. Implementation Reference

| Artifact | Location | Purpose |
| :--- | :--- | :--- |
| Redaction engine | `apps/api/internal/redaction/redaction.go` | Regex + schema-aware redaction of credentials, cookies, tokens |
| Evidence lifecycle | `apps/api/internal/evidence/lifecycle.go` | Signed URLs, retention sweep, cascading deletion |
| Config | `apps/api/internal/config/config.go` | `EvidenceConfig`, `RetentionConfig` settings |
| Tests | `*_test.go` alongside each package | Unit tests for redaction, signed URLs, retention |

---

## 9. Traceability

| Artifact | Reference |
| :--- | :--- |
| Planning reference | `P1-32` |
| Milestone | Phase 1 — Foundation & Core Architecture |
| Blocked by | `P1-10` Data Model; `P1-15` Secrets; `P1-20` Persistence; `P1-53` Tenant Isolation |
| Threat model | `docs/security/THREAT_MODEL.md` (T-10 data exposure, T-11 credential theft) |
| Secrets policy | `docs/security/SECRETS.md` |
| RBAC matrix | `docs/security/RBAC_MATRIX.md` |
| Finding schema | `docs/architecture/FINDING_SCHEMA.md` |
| Data model | `docs/architecture/DATA_MODEL.md` |

---

*Kelvin Security Platform — Phase 1 Engineering Backlog*
