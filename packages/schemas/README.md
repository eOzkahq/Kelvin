# Kelvin Schemas — Canonical Schema Library

Shared JSON/YAML schemas and validation fixtures consumed across all applications and services. No deployable entrypoint.

| Schema | Purpose | Specification Ref |
| :--- | :--- | :--- |
| `finding.v1.json` | Unified Finding & Evidence schema v1 | `P1-11`, `docs/architecture/FINDING_SCHEMA.md` |
| `api-envelope.schema.json` | Standard API success envelope | `P1-09`, `docs/api/API_STANDARDS.md` § 6 |
| `api-error.schema.json` | RFC 7807 Problem Details error envelope | `P1-09`, `docs/api/API_STANDARDS.md` § 7 |
| `fixtures/` | Positive and negative test fixtures for CI validation | `scripts/schema-validation/` |

**Boundary rule:** Packages may never import apps (`apps/*`). This package is strictly domain-agnostic and contract-focused.
