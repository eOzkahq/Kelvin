# Kelvin API Security-Testing Strategy

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Baseline |
| **Milestone** | Phase 1 — Foundation & Core Architecture (`P1-27`) |
| **Depends On** | `docs/security/RBAC_MATRIX.md` (`P1-12`), `docs/api/API_STANDARDS.md` (`P1-09`), `docs/security/THREAT_MODEL.md` (`P1-03`) |
| **Owner** | Product Security / Platform Engineering |
| **Classification** | Internal — Engineering Specification (Security-Critical) |

---

## 1. Purpose

This document defines Kelvin's automated API security-testing baseline. It exists because
authentication and authorization can appear correct during normal usage while failing under
adversarial conditions (cross-tenant resource access, privileged-field mass assignment,
administrative endpoints invoked with ordinary credentials, expired/revoked session reuse).

The baseline runs in CI on every push/PR and is fail-closed: any regression breaks the build.

---

## 2. Scope

Target: the Kelvin control-plane API (`/api/v1`, `apps/api`).

Covered areas (aligned to `docs/security/RBAC_MATRIX.md` §9):

| Area | What is tested | RBAC_MATRIX reference |
| :--- | :--- | :--- |
| Authentication | missing, malformed, expired, tampered, `alg:none`, wrong `aud`/`iss` credentials | `AC-TOKEN-01`…`AC-TOKEN-07` |
| Authorization / privilege boundary | role × endpoint × method matrix (Viewer, Analyst, TenantAdmin, SuperAdmin) | `AC-RBAC-01`…`AC-RBAC-08` |
| Cross-tenant IDOR / BOLA | Tenant A principal accessing Tenant B resources (read & write) | `AC-BOLA-01`…`AC-BOLA-06` |
| API boundaries | mass assignment, unexpected properties, oversized payloads, malformed identifiers | `AC-PRIV-01` |
| Information disclosure | RFC 7807 error envelopes, no stack traces / SQL / paths / secrets | `API_STANDARDS §7.3` |

---

## 3. Roles under test

The issue's role names map to Kelvin roles (`docs/security/RBAC_MATRIX.md` §2) as follows:

| Issue role | Kelvin role | Can create assessments | Can list assessments |
| :--- | :--- | :--- | :--- |
| Viewer | `READ_ONLY_AUDITOR` | no | yes |
| Analyst | `SECURITY_ANALYST` | yes | yes |
| TenantAdmin | `TENANT_ADMIN` | yes | yes |
| SuperAdmin | `PLATFORM_ADMIN` | no (no tenant data-plane) | no |

SuperAdmin is excluded from tenant data-plane access by design (`RBAC_MATRIX` B-6).

---

## 4. Test harness

### 4.1 Location

`apps/api/internal/security/` — a Go test package inside the `apps/api` module so it can
import the production `internal/auth`, `internal/httpapi`, and `internal/middleware`
packages (Go's `internal` visibility rule).

### 4.2 How it works

The harness spins an `httptest.Server` composing the **real** production middleware stack:

```
Correlation → AccessLog → Recover → BodyLimit → AuthN (auth.Middleware) →
AuthZ (auth.RequireRole / auth.TenantGuard) → stub route handlers
```

The stub handlers mirror the OpenAPI contract (`apps/api/openapi/openapi.yaml`) and the
RBAC matrix: they return 2xx only after the production authZ middleware has passed, and
404 for cross-tenant resources (indistinguishable from nonexistence, RBAC B-2). The harness
therefore tests the actual enforcement code, not a re-implementation of it.

### 4.3 Deterministic fixtures

`harness_test.go` defines fixed UUIDs for two tenants (Tenant A / Tenant B) and five
principals (one per role in Tenant A). Tokens are minted with the real
`auth.TokenService`. Deterministic fixtures make the suite reproducible across runs and CI
and remove dependence on a database or external services (no service containers required).

---

## 5. Test suites

| File | Coverage |
| :--- | :--- |
| `auth_test.go` | AC-TOKEN: missing header, malformed header, garbage token, expired, tampered signature, `alg:none`, wrong audience, wrong issuer, positive control |
| `rbac_test.go` | AC-RBAC: full role × endpoint × method matrix; role immutability (mass-assigned `role` rejected) |
| `idor_test.go` | AC-BOLA: cross-tenant read → 404 not_found (zero leakage), TenantGuard direct → 403, SuperAdmin data-plane ban (B-6) |
| `boundary_test.go` | mass assignment / unexpected fields → 422 `unknown_field`, oversized payload → 413, malformed identifiers → 422, unknown resource → 404, wrong content type → 415, empty body → 400, catch-all route → 404 problem |
| `envelope_test.go` | RFC 7807 conformance against `packages/schemas/api-error.schema.json`: required fields, problem URN, status range, UUID `correlation_id`, `errors[]` only on 422, `X-Correlation-ID` echo; panic → sanitized 500 (no stack/secret leak) |

---

## 6. Assertions

Every error response is asserted to:

- return `application/problem+json`;
- carry `type`, `title`, `status`, `correlation_id` (required by `api-error.schema.json`);
- use a `urn:kelvin:problem:*` URN and a status in `[400, 599]` matching the HTTP status line;
- carry a UUID `correlation_id` echoed from the `X-Correlation-ID` header;
- contain no stack traces, SQL, table/column names, file paths, internal hostnames, or
  secrets (`API_STANDARDS §7.3`);
- include `errors[]` **only** on `validation_failed` (422), per the schema.

Every 2xx response is asserted to use the standard success envelope (`success: true`).

---

## 7. CI integration

`.github/workflows/ci.yml` — job `security-test` ("Security test harness"):

- runs on `ubuntu-latest`;
- checks out the repo and sets up Go (from `apps/api/go.mod`);
- runs `go test -v -race ./internal/security/` in `apps/api`;
- is self-contained (no Postgres/Redis service containers).

It is wired in addition to the existing `go-test` job so the security baseline runs on every
push to `main`/`develop` and on every pull request.

Locally:

```bash
cd apps/api
go test -v -race ./internal/security/
# or from the repo root:
npm run test:go:security
```

---

## 8. Acceptance criteria coverage

| Criterion | Status |
| :--- | :--- |
| Documented API security-testing strategy | This document (`docs/security/SECURITY_TESTING.md`) |
| Authentication failure cases covered | `auth_test.go` |
| Authorization & privilege-boundary tests | `rbac_test.go` |
| Cross-tenant access tests (100% pass) | `idor_test.go` |
| Sensitive information disclosure tested & prevented | `envelope_test.go` + `assertNoInternalLeakage` |
| Security test harness executes in CI | `.github/workflows/ci.yml` `security-test` job |

---

## 9. Maintenance

- New endpoints require: an `x-required-permission` OpenAPI declaration, a registry entry,
  and at least one negative test (RBAC_MATRIX §11).
- When the real `sid`-based revocation store is implemented (Identity Layer), add an
  `AC-TOKEN-04` case asserting revoked sessions return 401.
- Review quarterly, and on any auth-stack, role, permission, or endpoint change.
