# Kelvin Common — Shared Utilities Library

Shared cross-cutting utilities (logging, errors, validation) consumed by all apps. No deployable entrypoint.

| Directory | Purpose |
| :--- | :--- |
| `logging/` | Structured logging helpers |
| `errors/` | Canonical error types |
| `validation/` | Shared validation helpers |

**Boundary rule:** Packages may never import apps. This package is domain-agnostic.
