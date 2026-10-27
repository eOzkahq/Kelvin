# Kelvin Common — Shared Utilities Library

Shared cross-cutting Go and TypeScript utilities (logging, errors, redaction, crypto) consumed by all applications. No deployable entrypoint.

| Directory | Purpose |
| :--- | :--- |
| `logging/` | Structured logging helpers and Zap redaction core |
| `errors/` | Canonical RFC 7807 error types and mapping helpers |
| `validation/` | Shared target and input validation helpers |
| `crypto/` | Fingerprinting and token validation helpers |

**Boundary rule:** Packages may never import apps (`apps/*`). This package is strictly domain-agnostic and dependency-light.
