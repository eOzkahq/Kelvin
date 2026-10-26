# Kelvin Schemas — Canonical Schema Library

Shared JSON/YAML schemas consumed by all apps. No deployable entrypoint.

| Schema | Purpose |
| :--- | :--- |
| `scan-profile.schema.json` | Scan profile validation (ADR-0005) |
| `finding.schema.json` | Canonical vulnerability finding schema |
| `assessment.schema.json` | Assessment job schema |
| `api-envelope.schema.json` | Standard API success envelope (`P1-09`, API_STANDARDS.md §6) |
| `api-error.schema.json` | RFC 7807 Problem Details error envelope (`P1-09`, API_STANDARDS.md §7) |

**Boundary rule:** Packages may never import apps. This package is domain-agnostic.
