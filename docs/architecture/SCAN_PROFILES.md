# Kelvin Security Platform — Scan Profiles

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Baseline — Peer-Reviewed |
| **Milestone** | Phase 1 — Foundation & Core Architecture (`P1-05`) |
| **Depends On** | `docs/security/THREAT_MODEL.md` (`P1-03`), `docs/security/ACCEPTABLE_USE.md` (`P1-04`) |
| **Owner** | Platform Engineering |
| **Review Cadence** | Quarterly, and whenever scanner adapter support is added |
| **Related Docs** | `docs/PRODUCT_VISION.md`, `docs/security/THREAT_MODEL.md`, `docs/security/ACCEPTABLE_USE.md`, `docs/ARCHITECTURE_AND_FEATURES.md`, `docs/MVP_AND_PHASE_BIFURCATION.md` |
| **Classification** | Internal — Engineering Specification |

---

## 1. Executive Summary

Monolithic security scanners typically expose a single "scan everything" toggle that either bombards fragile production systems with unthrottled active payloads or leaves critical business-logic flaws undetected behind superficial passive checks. Kelvin solves this with **declarative, version-controlled scan profiles** — structured configurations that specify request concurrency, execution budgets, hard timeout thresholds, and permitted check categories.

Scan profiles separate **policy** (what may be scanned and how intensely) from **mechanism** (how a specific scanner adapter executes a check). Profile parameters are expressed in JSON/YAML, validated against a strict schema, and enforced by the worker orchestration layer before any network traffic leaves a sandboxed worker. No scanner engine flag may be set outside the bounds of an approved profile.

---

## 2. Standard Scan Profiles

Kelvin ships with three built-in profiles. Built-in profiles are version-controlled, read-only, and may not be modified at runtime. Custom user profiles must conform to the schema in Section 4 and are subject to the validation and rejection rules in Section 7.

### 2.1 Profile: Passive Discovery (`kelvin.profile.passive.v1`)

**Intent:** Zero-network-traffic reconnaissance using only OSINT and public data sources. No packets are sent to the target host.

| Parameter | Value |
| :--- | :--- |
| `profile_id` | `kelvin.profile.passive.v1` |
| `impact_level` | `low` |
| `network_traffic_to_target` | `none` |
| `check_categories` | `discovery`, `passive` |
| `max_concurrent_connections` | `0` |
| `requests_per_second` | `0` |
| `hard_execution_deadline_seconds` | `600` (10 minutes) |
| `max_requests_per_target` | `0` |
| `authenticated_endpoints` | `false` |
| `active_fuzzing` | `false` |
| `destructive_checks` | `false` |
| `admin_signoff_required` | `false` |
| `permitted_targets` | Verified domains / subdomains / CIDRs |
| `excluded_uris` | `/login`, `/signin`, `/auth/*`, `/oauth/*`, `/sso/*`, `/checkout`, `/pay`, `/payment/*` |

**Typical checks:** OSINT gathering, DNS enumeration, certificate transparency logs, public WHOIS, passive TLS configuration observation.

**Authorization:** Asset ownership verification not required for passive-only OSINT; required if any network traffic to the target is involved.

---

### 2.2 Profile: Standard Automated Baseline (`kelvin.profile.standard.v1`)

**Intent:** Non-destructive, rate-limited automated assessment suitable for routine scanning of verified production assets.

| Parameter | Value |
| :--- | :--- |
| `profile_id` | `kelvin.profile.standard.v1` |
| `impact_level` | `medium` |
| `network_traffic_to_target` | `limited` |
| `check_categories` | `discovery`, `passive` |
| `max_concurrent_connections` | `10` |
| `requests_per_second` | `50` |
| `hard_execution_deadline_seconds` | `1800` (30 minutes) |
| `max_requests_per_target` | `5000` |
| `authenticated_endpoints` | `false` |
| `active_fuzzing` | `false` |
| `destructive_checks` | `false` |
| `admin_signoff_required` | `false` |
| `permitted_targets` | Verified domains / subdomains / CIDRs |
| `excluded_uris` | `/login`, `/signin`, `/auth/*`, `/oauth/*`, `/sso/*`, `/checkout`, `/pay`, `/payment/*` |

**Typical checks:** Service banner detection, version fingerprinting, missing-patch checks, HTTP header analysis, TLS configuration review, passive content discovery.

**Authorization:** Asset ownership verification required (DNS TXT / `.well-known` / LoA).

---

### 2.3 Profile: Deep Authorized Assessment (`kelvin.profile.deep.v1`)

**Intent:** Authorized, active security assessment including authenticated endpoints and parameter fuzzing. Requires explicit multi-factor administrator sign-off and a scheduled execution window.

| Parameter | Value |
| :--- | :--- |
| `profile_id` | `kelvin.profile.deep.v1` |
| `impact_level` | `high` |
| `network_traffic_to_target` | `active` |
| `check_categories` | `discovery`, `passive`, `active` |
| `max_concurrent_connections` | `20` |
| `requests_per_second` | `100` |
| `hard_execution_deadline_seconds` | `14400` (4 hours) |
| `max_requests_per_target` | `50000` |
| `authenticated_endpoints` | `true` (scoped test accounts only) |
| `active_fuzzing` | `true` |
| `destructive_checks` | `false` |
| `admin_signoff_required` | `true` |
| `permitted_targets` | Verified domains / subdomains / CIDRs with active authorization |
| `excluded_uris` | `/login`, `/signin`, `/auth/*`, `/oauth/*`, `/sso/*`, `/checkout`, `/pay`, `/payment/*`, admin interfaces not owned by testing organization |

**Typical checks:** All standard checks plus authenticated application scanning, active parameter fuzzing, business-logic test cases, authenticated vulnerability verification.

**Authorization:** Asset ownership verification **and** multi-factor admin sign-off within an approved schedule window (see `docs/security/ACCEPTABLE_USE.md` §7).

---

## 3. Check Category Tagging

Every scanner check must be tagged with exactly one category. Categories determine which profiles may execute the check and what enforcement limits apply.

| Category | Description | Default State | Permitted In Profiles |
| :--- | :--- | :--- | :--- |
| `discovery` | Passive OSINT and service discovery (no target traffic) | Enabled | passive, standard, deep |
| `passive` | Non-intrusive checks observing target responses (banner grab, TLS config, headers) | Enabled | passive, standard, deep |
| `active` | Active checks sending crafted payloads (parameter fuzzing, injection probes) | **Disabled by default** | deep only |
| `destructive` | Checks that may modify state, crash services, or exfiltrate data | **Disabled by default** | none (prohibited) |

**Default-deny rule:** `active` and `destructive` checks are disabled by default across all baseline profiles. `active` checks are only available in `kelvin.profile.deep.v1`. `destructive` checks are never available in any shipped profile.

Any attempt to enable `destructive` checks in a custom profile is rejected with error `ERR_PROFILE_DESTRUCTIVE_CHECKS_PROHIBITED` (Section 7).

---

## 4. Profile Schema (JSON Schema)

The authoritative schema for scan profiles is published at `docs/architecture/schemas/scan-profile.schema.json` and summarized below. All profiles — built-in and custom — must validate against this schema before being accepted by the worker orchestration layer.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://kelvin.security/schema/scan-profile/v1",
  "title": "Kelvin Scan Profile",
  "type": "object",
  "required": [
    "profile_id",
    "version",
    "impact_level",
    "network_traffic_to_target",
    "check_categories",
    "execution_budget",
    "hard_execution_deadline_seconds",
    "authenticated_endpoints",
    "active_fuzzing",
    "destructive_checks",
    "admin_signoff_required",
    "excluded_uris"
  ],
  "additionalProperties": false,
  "properties": {
    "profile_id": {
      "type": "string",
      "pattern": "^kelvin\\.profile\\.[a-z0-9_-]+\\.v[0-9]+$",
      "description": "Unique profile identifier. Custom profiles must use a non-kelvin namespace (e.g., org.acme.profile.custom.v1)."
    },
    "version": {
      "type": "string",
      "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$",
      "description": "Semantic version of the profile definition."
    },
    "impact_level": {
      "type": "string",
      "enum": ["low", "medium", "high"],
      "description": "Operational impact classification for approval routing."
    },
    "network_traffic_to_target": {
      "type": "string",
      "enum": ["none", "limited", "active"],
      "description": "Expected network intensity against the target host."
    },
    "check_categories": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["discovery", "passive", "active", "destructive"]
      },
      "uniqueItems": true,
      "minItems": 1,
      "description": "Permitted check categories. 'destructive' is prohibited in all profiles."
    },
    "execution_budget": {
      "type": "object",
      "required": ["max_concurrent_connections", "requests_per_second", "max_requests_per_target"],
      "additionalProperties": false,
      "properties": {
        "max_concurrent_connections": {
          "type": "integer",
          "minimum": 0,
          "maximum": 100,
          "description": "Maximum concurrent connections to a single target."
        },
        "requests_per_second": {
          "type": "integer",
          "minimum": 0,
          "maximum": 1000,
          "description": "Maximum HTTP requests per second per target."
        },
        "max_requests_per_target": {
          "type": "integer",
          "minimum": 0,
          "maximum": 100000,
          "description": "Total request budget per target per assessment."
        }
      },
      "description": "Mandatory execution budgets. All three fields are required."
    },
    "hard_execution_deadline_seconds": {
      "type": "integer",
      "minimum": 60,
      "maximum": 86400,
      "description": "Hard execution deadline in seconds. Assessment is forcibly terminated at this limit."
    },
    "authenticated_endpoints": {
      "type": "boolean",
      "description": "Whether authenticated scanning is permitted."
    },
    "active_fuzzing": {
      "type": "boolean",
      "description": "Whether active parameter fuzzing is permitted."
    },
    "destructive_checks": {
      "type": "boolean",
      "const": false,
      "description": "Must be false. Destructive checks are prohibited in all profiles."
    },
    "admin_signoff_required": {
      "type": "boolean",
      "description": "Whether multi-factor admin sign-off is required before execution."
    },
    "permitted_targets": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": ["verified_domain", "verified_subdomain", "verified_cidr"]
      },
      "uniqueItems": true,
      "description": "Target classes permitted under this profile."
    },
    "excluded_uris": {
      "type": "array",
      "items": {
        "type": "string",
        "pattern": "^/.*"
      },
      "uniqueItems": true,
      "description": "URI path prefixes excluded from scanning."
    },
    "custom_scanner_flags": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "allow_unknown_flags": {
          "type": "boolean",
          "const": false
        },
        "permitted_flags": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "description": "Explicitly permitted scanner-specific flags. All other flags are rejected."
        }
      },
      "description": "Optional scanner-specific flag allow-list. Unknown flags are rejected by default."
    }
  }
}
```

**Schema validation rules:**
* `profile_id` must match `^kelvin\.profile\.[a-z0-9_-]+\.v[0-9]+$` for built-in profiles, or a non-kelvin namespace for custom profiles.
* `destructive_checks` must be `false` (constrained by JSON Schema `const`).
* `execution_budget` is mandatory — all three sub-fields (`max_concurrent_connections`, `requests_per_second`, `max_requests_per_target`) are required.
* `hard_execution_deadline_seconds` is mandatory, bounded between 60 and 86,400 seconds.
* `additionalProperties: false` at every level — unknown keys cause validation failure.
* `custom_scanner_flags.allow_unknown_flags` must be `false`; unknown scanner flags are rejected.

---

## 5. Built-In Profile Definitions

The following YAML representations are the canonical built-in profiles shipped with Kelvin.

### 5.1 `kelvin.profile.passive.v1`

```yaml
profile_id: kelvin.profile.passive.v1
version: "1.0.0"
impact_level: low
network_traffic_to_target: none
check_categories:
  - discovery
  - passive
execution_budget:
  max_concurrent_connections: 0
  requests_per_second: 0
  max_requests_per_target: 0
hard_execution_deadline_seconds: 600
authenticated_endpoints: false
active_fuzzing: false
destructive_checks: false
admin_signoff_required: false
permitted_targets:
  - verified_domain
  - verified_subdomain
  - verified_cidr
excluded_uris:
  - /login
  - /signin
  - /auth/*
  - /oauth/*
  - /sso/*
  - /checkout
  - /pay
  - /payment/*
custom_scanner_flags:
  allow_unknown_flags: false
  permitted_flags: []
```

### 5.2 `kelvin.profile.standard.v1`

```yaml
profile_id: kelvin.profile.standard.v1
version: "1.0.0"
impact_level: medium
network_traffic_to_target: limited
check_categories:
  - discovery
  - passive
execution_budget:
  max_concurrent_connections: 10
  requests_per_second: 50
  max_requests_per_target: 5000
hard_execution_deadline_seconds: 1800
authenticated_endpoints: false
active_fuzzing: false
destructive_checks: false
admin_signoff_required: false
permitted_targets:
  - verified_domain
  - verified_subdomain
  - verified_cidr
excluded_uris:
  - /login
  - /signin
  - /auth/*
  - /oauth/*
  - /sso/*
  - /checkout
  - /pay
  - /payment/*
custom_scanner_flags:
  allow_unknown_flags: false
  permitted_flags: []
```

### 5.3 `kelvin.profile.deep.v1`

```yaml
profile_id: kelvin.profile.deep.v1
version: "1.0.0"
impact_level: high
network_traffic_to_target: active
check_categories:
  - discovery
  - passive
  - active
execution_budget:
  max_concurrent_connections: 20
  requests_per_second: 100
  max_requests_per_target: 50000
hard_execution_deadline_seconds: 14400
authenticated_endpoints: true
active_fuzzing: true
destructive_checks: false
admin_signoff_required: true
permitted_targets:
  - verified_domain
  - verified_subdomain
  - verified_cidr
excluded_uris:
  - /login
  - /signin
  - /auth/*
  - /oauth/*
  - /sso/*
  - /checkout
  - /pay
  - /payment/*
custom_scanner_flags:
  allow_unknown_flags: false
  permitted_flags: []
```

---

## 6. Mapping Rules: Abstract Profile → Scanner Engine Flags

Profile parameters are abstract policy values. Scanner adapters translate them into engine-specific invocation flags. The mapping below is mandatory for all built-in and third-party scanner adapters.

| Profile Parameter | Nuclei Flag | ZAP Flag | OpenVAS Flag | Trivy Flag | Enforcement |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `requests_per_second` | `-rate-limit N` | `-spider.maxDuration` + pacing | Task `max_hosts` / `max_checks` | `--timeout` | Worker enforces via rate limiter |
| `max_concurrent_connections` | `-c N` | Thread count | Scanner `max_hosts` | N/A | Worker enforces via semaphore |
| `hard_execution_deadline_seconds` | `-timeout N` | Scan timeout | Task `timeout` | `--timeout` | Worker kills process at deadline |
| `max_requests_per_target` | Custom counter | Custom counter | Custom counter | Custom counter | Worker enforces via request counter |
| `active_fuzzing: false` | Exclude `fuzzing` templates | Disable active scan policy | Disable intrusive NVTs | N/A | Adapter filter rejects matching checks |
| `destructive_checks: false` | Exclude `dos` / `exploit` templates | Deny destructive policy | Deny safe-check-off | N/A | Hard reject — profile invalid if true |
| `authenticated_endpoints: false` | No `-auth` / cookie injection | No authenticated context | No credentials | N/A | Adapter strips auth headers |
| `excluded_uris` | `-exclude` path patterns | Context exclude URLs | Target exclusions | `--skip-dirs` | Adapter filters target URLs |

**Mapping rule requirements:**
1. Every scanner adapter must document its flag-to-profile mapping in its adapter registry entry.
2. Adapters must reject any profile parameter they cannot faithfully map — never silently ignore or approximate.
3. If a scanner cannot enforce a given budget (e.g., requests-per-second), the adapter must either implement client-side throttling or refuse the profile with error `ERR_ADAPTER_BUDGET_UNENFORCEABLE`.

---

## 7. Validation & Rejection Logic

The profile parser runs at profile registration time and again at assessment enqueue time. All validations produce explicit, structured errors — never silent fallback to defaults.

### 7.1 Schema Validation Errors

| Error Code | Condition | Message |
| :--- | :--- | :--- |
| `ERR_PROFILE_SCHEMA_INVALID` | Profile fails JSON Schema validation | "Profile `<profile_id>` is invalid: `<schema-validation-detail>`" |
| `ERR_PROFILE_MISSING_BUDGET` | `execution_budget` or any sub-field missing | "Profile `<profile_id>` missing mandatory execution_budget fields" |
| `ERR_PROFILE_DESTRUCTIVE_CHECKS` | `destructive_checks` is `true` | "Profile `<profile_id>` prohibits destructive_checks" |
| `ERR_PROFILE_UNKNOWN_FIELD` | `additionalProperties: false` violation | "Profile `<profile_id>` contains unknown field `<field>`" |
| `ERR_PROFILE_ID_FORMAT` | `profile_id` pattern mismatch | "Profile ID `<profile_id>` must match required pattern" |

### 7.2 Semantic Validation Errors

| Error Code | Condition | Message |
| :--- | :--- | :--- |
| `ERR_PROFILE_CATEGORY_PROFILE_MISMATCH` | `active` or `destructive` in non-deep profile | "Category `<category>` not permitted in profile `<profile_id>`" |
| `ERR_PROFILE_ADMIN_SIGNOFF_MISSING` | Deep profile requested without admin sign-off | "Profile `<profile_id>` requires multi-factor admin sign-off" |
| `ERR_PROFILE_SCHEDULE_OUTSIDE_WINDOW` | Assessment outside approved schedule window | "Assessment scheduled outside approved window for profile `<profile_id>`" |
| `ERR_PROFILE_ADAPTER_UNENFORCEABLE` | Adapter cannot enforce a budget parameter | "Adapter `<adapter>` cannot enforce `<parameter>` for profile `<profile_id>`" |
| `ERR_PROFILE_UNKNOWN_SCANNER_FLAG` | `custom_scanner_flags` contains non-allow-listed flag | "Scanner flag `<flag>` not in permitted_flags for profile `<profile_id>`" |

### 7.3 Rejection Behavior

1. **At registration:** A custom profile that fails validation is rejected outright; it is not stored and cannot be referenced by assessments.
2. **At enqueue:** If an assessment references a profile that no longer validates (e.g., schema updated, adapter retired), the job is rejected with `ERR_PROFILE_SCHEMA_INVALID` and no worker is dispatched.
3. **At runtime:** If a worker attempts to exceed any budget (concurrency, rate, request count, deadline), the orchestration layer throttles or terminates the job and logs a security event.
4. **No silent overrides:** User-supplied profile overrides are merged only through the schema-validated path. Unknown or dangerous overrides produce explicit errors and block execution.

---

## 8. Custom User Profiles

Users may define custom profiles subject to all schema and semantic rules in Sections 4–7.

| Constraint | Requirement |
| :--- | :--- |
| `profile_id` namespace | Must use a non-kelvin namespace (e.g., `org.acme.profile.custom.v1`) |
| `destructive_checks` | Must be `false`; hard-rejected otherwise |
| `execution_budget` | Mandatory; bounded per schema |
| `admin_signoff_required` | `true` required if `check_categories` includes `active` |
| `custom_scanner_flags` | `allow_unknown_flags` must be `false`; only `permitted_flags` allowed |
| Versioning | Custom profiles are version-controlled; changes create a new version, never mutate in place |
| Approval | Custom profiles with `impact_level: high` require admin sign-off before first use |

---

## 9. Governance & Change Control

1. **Built-in profiles are immutable.** Changes to `kelvin.profile.*.v1` profiles require a new version (`v2`, `v3`, …) and a formal review by Product, Engineering, and Security.
2. **Custom profiles must validate.** No custom profile is accepted without passing JSON Schema validation and semantic checks.
3. **Destructive checks are permanently prohibited.** No profile — built-in or custom — may enable `destructive_checks` without a formal AUP amendment (see `docs/security/ACCEPTABLE_USE.md`).
4. **Review cadence.** This document and the schema are reviewed quarterly and whenever a new scanner adapter is integrated.
5. **Adapter mapping documentation.** Every scanner adapter must publish its flag-to-profile mapping; adapters without documentation are not approved for production use.

---

## 10. Traceability

| Artifact | Reference |
| :--- | :--- |
| Planning reference | `P1-05` |
| Milestone | Phase 1 — Foundation & Core Architecture |
| Blocked by | `P1-03` — `docs/security/THREAT_MODEL.md`; `P1-04` — `docs/security/ACCEPTABLE_USE.md` |
| Product vision & non-goals | `docs/PRODUCT_VISION.md` |
| Threat model | `docs/security/THREAT_MODEL.md` |
| Acceptable use policy | `docs/security/ACCEPTABLE_USE.md` |
| System architecture | `docs/ARCHITECTURE_AND_FEATURES.md` |
| MVP & phase bifurcation | `docs/MVP_AND_PHASE_BIFURCATION.md` |
| User personas & journeys | `docs/product/PERSONAS.md` |
| Engineering roadmap | `docs/ROADMAP.md` |

---

*Kelvin Security Platform — Phase 1 Engineering Backlog*
