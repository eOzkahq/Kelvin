# Kelvin Worker — Sandboxed Scanner Fleet

Ephemeral, rootless container workers that execute scanner adapters (Nmap, Nuclei, OpenVAS, Trivy, etc.) against verified targets within strict egress bounds.

**Technology:** Go 1.22+ daemon (ADR-0001)  
**Sandboxing:** Rootless OCI containers, seccomp/AppArmor profiles, read-only rootfs (ADR-0005)  
**Execution Budget:** CPU/memory cgroups v2 quotas, `hard_execution_deadline_seconds`  
**Broker Client:** Go Redis client (`redis/go-redis`) authenticated via short-lived worker tokens (ADR-0003)

| Directory | Purpose |
| :--- | :--- |
| `cmd/runner/` | Worker daemon entrypoint (`cmd/runner/main.go`) |
| `internal/adapters/` | Modular scanner adapter implementations (CLI/JSON wrappers) |
| `internal/sandbox/` | OCI container sandboxing runtime (security-critical) |
| `internal/egress/` | Egress proxy & socket DNS pinning filter (security-critical) |
| `pkg/` | Reusable worker library code |
| `configs/` | Worker configuration templates |
| `deploy/` | Worker container deployment manifests |

**Boundary rule:** Workers never initiate direct connections to the control plane database or internal network (SYSTEM_ARCHITECTURE.md NB-06). Results stream one-way via the broker or findings ingestion endpoint.
