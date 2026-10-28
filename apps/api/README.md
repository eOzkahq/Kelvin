# Kelvin API — Control Plane

The API control plane service. Implements authentication & tenant RBAC, target scope & validation, assessment job orchestration, and finding normalization/deduplication.

**Technology:** Go 1.22+ standard library `net/http` (ADR-0001)  
**Database:** PostgreSQL 15+ with Row-Level Security (ADR-0002)  
**Job Broker:** Redis 7+ BullMQ pattern (ADR-0003)  
**Logging:** Structured JSON via `go.uber.org/zap`  
**Configuration:** `spf13/viper`

| Directory | Purpose |
| :--- | :--- |
| `cmd/` | Application entrypoints (`cmd/server/main.go`) |
| `internal/auth/` | Authentication & tenant RBAC service |
| `internal/scope/` | Target scope & validation service (security-critical, anti-SSRF) |
| `internal/orchestrator/` | Assessment job orchestrator & state machine |
| `internal/findings/` | Finding normalization & deduplication service |
| `pkg/` | Reusable library code safe for import by other apps |
| `configs/` | Service configuration templates |
| `openapi/` | OpenAPI 3.1 API contract — source of truth (`openapi.yaml`, `P1-09`) |
| `deploy/` | Deployment manifests (K8s, Docker) |

**Boundary rule:** `internal/` is strictly private to this application. No other application or package may import `apps/api/internal/*` (enforced via Go packaging semantics and `REPOSITORY_LAYOUT.md`).
