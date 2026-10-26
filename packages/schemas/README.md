# Kelvin Schemas — Canonical Schema Library

Shared JSON/YAML schemas consumed by all apps. No deployable entrypoint.

| Schema | Purpose |
| :--- | :--- |
| `scan-profile.schema.json` | Scan profile validation (ADR-0005) |
| `finding.schema.json` | Canonical vulnerability finding schema |
| `assessment.schema.json` | Assessment job schema |

**Boundary rule:** Packages may never import apps. This package is domain-agnostic.
