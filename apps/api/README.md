# Kelvin API — Control Plane

The API control plane service. Implements authentication & tenant RBAC, target scope & validation, assessment job orchestration, and finding normalization/deduplication.

**Technology:** Go (ADR-0001)  
**Database:** PostgreSQL (ADR-0002)  
**Job broker:** Redis/BullMQ (ADR-0003)

| Directory | Purpose |
| :--- | :--- |
| `cmd/` | Application entrypoints |
| `internal/auth/` | Auth & tenant RBAC service |
| `internal/scope/` | Target scope & validation service (security-critical) |
| `internal/orchestrator/` | Assessment job orchestrator |
| `internal/findings/` | Finding normalization & deduplication service |
| `pkg/` | Library code safe for import by other apps |
| `configs/` | Configuration files |
| `openapi/` | OpenAPI 3.1 API contract — source of truth (`openapi.yaml`, `P1-09`) |
| `deploy/` | Deployment manifests (K8s, Docker) |

**Boundary rule:** `internal/` is private to this app. No other app or package may import `apps/api/internal/*`.
