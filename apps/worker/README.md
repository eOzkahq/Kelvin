# Kelvin Worker — Sandboxed Scanner Fleet

Ephemeral, rootless container workers that execute scanner adapters (Nmap, Nuclei, OpenVAS, Trivy, etc.) against verified targets within strict egress bounds.

**Technology:** Go (ADR-0001)  
**Sandboxing:** Rootless containers, seccomp/AppArmor, read-only root FS (ADR-0005)

| Directory | Purpose |
| :--- | :--- |
| `cmd/runner/` | Worker daemon entrypoint |
| `internal/adapters/` | Scanner adapter implementations |
| `internal/sandbox/` | Container sandboxing (security-critical) |
| `internal/egress/` | Egress proxy & DNS pinning (security-critical) |
| `pkg/` | Library code safe for import by other apps |
| `configs/` | Worker configuration |
| `deploy/` | Worker deployment manifests |

**Boundary rule:** Workers never initiate contact with the control plane internals (SYSTEM_ARCHITECTURE.md NB-06). Results stream one-way to the Findings service.
