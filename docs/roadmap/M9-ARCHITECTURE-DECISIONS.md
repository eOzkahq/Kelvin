# KELVIN — Milestone 9 (M9) Architecture Decisions (ADR Index)

**Project:** KELVIN Security Assessment Platform  
**Scope:** Milestone 9 Execution (M9.1 - M9.7)  
**Last Updated:** Tuesday, November 17, 2026

---

## Architecture Decision Records (M9 Series)

### ADR-M9-01: Redis Streams Consumer Group Lease & Reclaim Semantics (M9.1)
- **Status:** Proposed
- **Context:** Worker requires reliable, idempotent job consumption from Redis Streams without risk of duplicate execution during worker restart or network partition.
- **Decision:** Utilize Redis Consumer Groups with `XREADGROUP`, periodic `XAUTOCLAIM` for dead consumer eviction (> 60s idle), explicit `XACK` only upon durable database persistence, and Redis-backed distributed lease locks with TTL for active job execution.
- **Consequences:** Safe against worker crash and network split; prevents duplicate scan invocations.

### ADR-M9-02: Isolated Rootless Podman & crun Execution Runtime (M9.2)
- **Status:** Proposed
- **Context:** Scanners execute untrusted or aggressive networking tools that must never touch the host filesystem, Docker socket, host namespaces, or cloud credentials.
- **Decision:** Execute every scanner container via rootless Podman using `crun`, dropping all Linux capabilities except `NET_RAW` where strictly required for SYN scan, mounting read-only root filesystems, restricting memory/CPU quotas, and isolating stdout/stderr through bounded streams.
- **Consequences:** Eliminates container breakout risk; protects Oracle host credentials.

### ADR-M9-03: Immutable Versioned Scope Snapshots & Multi-Layer SSRF Defense (M9.3)
- **Status:** Proposed
- **Context:** Users register custom targets which could be weaponized to scan internal cloud metadata (`169.254.169.254`), private RFC1918 ranges, or escape scope via DNS rebinding / HTTP redirects.
- **Decision:** Bind every assessment to an immutable cryptographic scope snapshot. Enforce centralized SSRF validation that resolves DNS, validates IP ranges against a strict public allowlist, pins IP addresses where supported, and re-validates redirects at the proxy/client level.
- **Consequences:** Guarantees zero SSRF or scope creep even if DNS changes mid-scan.

### ADR-M9-04: Controlled Default-Deny Egress Proxy (M9.4)
- **Status:** Proposed
- **Context:** Containers must not have direct route access to arbitrary IP addresses or ports.
- **Decision:** Direct container network egress through a controlled egress proxy requiring ephemeral execution tokens, enforcing target destination IP and approved ports, and rejecting any unapproved outbound traffic with audit logging.
- **Consequences:** Guarantees all scanner traffic adheres strictly to authorized assessment scope.
