# Kelvin — Assessment Execution Isolation

**Document Control**

| Field | Value |
| :--- | :--- |
| **Status** | Baseline — Peer Review Required (Security review mandatory) |
| **Milestone** | Phase 1 — Foundation & Core Architecture (`P1-28`) |
| **Depends On** | `docs/architecture/SYSTEM_ARCHITECTURE.md` (`P1-06`), `docs/architecture/decisions/ADR-0005.md` (`P1-07`), `docs/architecture/JOB_LIFECYCLE.md`, `docs/architecture/JOB_QUEUE.md`, `docs/architecture/SCAN_PROFILES.md`, `docs/security/THREAT_MODEL.md` (`P1-03`) |
| **Owner** | Platform Engineering / Product Security |
| **Classification** | Internal — Engineering Specification (Security-Critical) |

---

## 1. Executive Summary

Kelvin executes third-party scanner binaries (Nmap, Nuclei, OpenVAS, Trivy, …) against potentially hostile target hosts. A scanner vulnerability, malicious target response, or misconfigured check must **never** compromise the control plane, exfiltrate secrets or database credentials, or deny service to other assessments.

This document defines the execution isolation boundaries and the controlled interface through which the API control plane delegates assessment work to sandboxed workers. It is the normative reference for the `apps/worker/internal/sandbox` package and scanner adapter contracts.

---

## 2. Trust Boundaries

The platform is divided into four execution zones. Each zone trusts the ones "above" it less and enforces a strict boundary.

```
+---------------------------------------------------------------------------+
| TRUSTED ZONE — Core Platform (API, DB, Redis, Findings Service)           |
|  High trust. Authenticated, mTLS, tenant-scoped. Never executes scanners. |
+---------------------------------------------------------------------------+
                                  | enqueue job (one-way)
                                  v
+---------------------------------------------------------------------------+
| SEMI-TRUSTED ZONE — Worker Daemon (Go orchestrator)                      |
|  Pulls jobs from broker, provisions sandbox, enforces deadlines/heartbeats.|
|  Never initiates contact with control plane internals except via broker.  |
+---------------------------------------------------------------------------+
                                  | spawn rootless container
                                  v
+---------------------------------------------------------------------------+
| UNTRUSTED EXECUTION — Isolated Sandbox (Rootless OCI Container)           |
|  Scanner adapter + target traffic. No host creds, no Docker socket,       |
|  read-only rootfs, dropped caps, bounded egress, cgroups limits.          |
+---------------------------------------------------------------------------+
                                  | outbound scans only
                                  v
+---------------------------------------------------------------------------+
| EXTERNAL / TARGET ZONE — Verified Targets Only                            |
|  Hostile/untrusted responses. Egress allow-listed; RFC1918/metadata deny. |
+---------------------------------------------------------------------------+
```

### 2.1 Zone responsibilities

| Zone | Trust | Responsibility | May initiate contact with |
| :--- | :--- | :--- | :--- |
| **Core Platform** | High | Auth/RBAC, scope validation, job orchestration, finding normalization, persistence | Queue (enqueue), DB |
| **Worker Daemon** | Semi | Dequeue job, provision sandbox, enforce hard deadline, heartbeat, stream results to Findings Service | Queue (dequeue/heartbeat), Findings Service |
| **Sandbox** | None | Execute scanner adapter against target within bounds | Target (egress allow-list), Queue (heartbeat) |
| **Target** | None | Hostile system under assessment | — (scanned only) |

**Critical boundary rule (SYSTEM_ARCHITECTURE §4.2 NB-06):** The sandbox and worker daemon **never** initiate inbound connections to the API, auth service, or database. Worker-to-control-plane traffic is one-way results return only. A compromised sandbox cannot reach the control plane or internal networks.

---

## 3. Container Isolation Mechanisms

All scanner execution happens inside rootless OCI containers (Docker/Podman-compatible runtime) provisioned by the worker daemon through the `sandbox.Executor` interface. The following hardening profile is mandatory for every container:

### 3.1 Privilege & user isolation

| Control | Requirement | Rationale |
| :--- | :--- | :--- |
| Rootless execution | Container runs as non-root user; container UID 0 mapped to unprivileged host UID via user namespace | No container process runs as root (UID ≠ 0) |
| No privileged mode | `--privileged` forbidden | Prevents host access |
| No Docker socket | `/var/run/docker.sock` not mounted | Prevents container breakout via daemon |
| No host namespace sharing | No PID/IPC/UTS/Network namespace sharing with host | Limits escape surface |
| Non-root `USER` | Dockerfile `USER` directive; verified at provisioning | Defense in depth |

### 3.2 Dropped Linux capabilities

All capabilities are dropped by default; none are added unless a scanner demonstrably requires them (reviewed case-by-case, e.g. `CAP_NET_RAW` for raw-socket scanning):

| Capability | Default | Notes |
| :--- | :--- | :--- |
| `CAP_ALL` | Dropped | `--cap-drop=ALL` |
| `CAP_NET_RAW` | Not added | Requires explicit security review; not granted by default |
| `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_MODULE` | Never added | Not required by any shipped scanner |

### 3.3 Filesystem restrictions

| Control | Requirement |
| :--- | :--- |
| Read-only rootfs | `--read-only` root filesystem; no persistent state |
| Ephemeral tmpfs | `tmpfs` mounts for `/tmp` and `/run` with `noexec,nosize` bounds; cleared on container removal |
| No host mounts | No host paths mounted into the container |
| Fresh filesystem per job | Container removed after each job; no residual state or credentials |

### 3.4 Security profiles

| Control | Requirement |
| :--- | :--- |
| seccomp | Profile restricting dangerous syscalls (`mount`, `ptrace`, `reboot`, module loading, clock adjustments) |
| AppArmor / SELinux | Profile restricting file, network, and process operations |
| Profile versioning | seccomp/AppArmor profiles versioned and reviewed alongside scanner adapter changes |

### 3.5 Resource & execution bounds

| Control | Requirement | Source |
| :--- | :--- | :--- |
| Memory limit | cgroups v2 memory limit per worker profile | `SCAN_PROFILES.md` execution_budget |
| CPU quota | cgroups v2 CPU quota/cores limit | `SCAN_PROFILES.md` execution_budget |
| pids limit | `pids-limit` to prevent fork bombs | Defensive |
| Hard execution deadline | Worker supervisor kills container at `hard_execution_deadline_seconds` | `Store.SetDeadline` + supervisor timeout |
| Network timeouts | Read/connection timeouts on all adapter network calls | Defensive |
| Request budget | Per-target request counter enforced by orchestrator | `max_requests_per_target` |

---

## 4. Network Restrictions

| Control | Requirement |
| :--- | :--- |
| Egress proxy | All worker outbound traffic passes through strict egress proxy |
| Allow-list | Verified target IPs/domains only (asset ownership verification) |
| Absolute deny-list | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`, `169.254.0.0/16` (incl. `169.254.169.254` cloud metadata), `224.0.0.0/4`, `240.0.0.0/4` |
| DNS pinning | Pinning resolver, TTL=0, anti-rebind, single resolution at validation time |
| Rate limits | Per-worker and per-target connection/request budgets |
| Inbound | Worker initiates no inbound connections; outbound only to broker (jobs/heartbeats) and Findings Service (sanitized results) |

Reference: `SYSTEM_ARCHITECTURE.md` §4.2/4.3 (NB-05, NB-06, NB-07).

---

## 5. Scanner Adapter Contract

Scanner adapters are the only code that executes inside the sandbox. They are treated as untrusted: their input is validated at ingestion and their output is validated at egress.

### 5.1 Task ingestion (control plane → sandbox)

The worker daemon validates and normalizes each job before dispatch:

* `job.ID`, `job.AssessmentID`, `job.TenantID` are valid UUIDs (validated at enqueue by `Message.Validate`).
* `job.TenantID` is non-empty and non-nil; jobs without tenant context are rejected before execution.
* `job.Type` is a registered adapter name (e.g. `nuclei`, `nmap`, `zap`, `trivy`); unknown types fail the job.
* The target is validated against the approved scope policy (`scope.Policy.Validate`): prohibited ranges (RFC1918, loopback, link-local, metadata) rejected, out-of-scope hosts rejected.
* `hard_execution_deadline_seconds` from the scan profile bounds execution; the supervisor kills the container at this deadline.

### 5.2 Finding egress (sandbox → control plane)

Scanner output is **untrusted input** and is never persisted or rendered directly:

* Raw scanner stdout/stderr are captured with a size cap; oversized output is truncated and logged as a security event.
* Findings are normalized into the canonical `finding.v1.json` schema by the worker/Findings Service.
* Every finding is validated against `packages/schemas/finding.v1.json` (draft 2020-12) before ingestion:
  - Required fields present: `schema_version`, `title`, `severity`, `confidence`, `target`, `vulnerability`, `scanner`, `discovered_at`
  - `schema_version` matches `^1\.[0-9]+$`
  - `severity` is one of `CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL`
  - `confidence` is within `0..1`
  - `target.asset` is present
  - `scanner.name` and `scanner.adapter_version` are present
  - `server-assigned` fields (`id`, `fingerprint`, `status`, `evidence[].id`) are ignored if supplied by the scanner and recomputed server-side.
* Findings failing validation are rejected (not persisted); the job is not marked COMPLETED until validation passes.
* Credentials, tokens, and keys are redacted from evidence before persistence (FINDING_SCHEMA §6).
* Evidence inline previews are size-capped (64 KiB default); large artifacts are referenced by checksum out-of-band.

### 5.3 Adapter interface

```go
type Executable interface {
    // Name returns the registered adapter name (e.g. "nuclei").
    Name() string
    // Execute runs the scanner inside the sandbox and returns structured output.
    // The context carries the hard deadline; cancellation kills the container.
    Execute(ctx context.Context, task Task) (Result, error)
}
```

`Task` carries the validated job inputs; `Result` carries exit code, duration, capped stdout/stderr, OOM/deadline-exceeded flags, and the raw findings payload (untrusted, subject to schema validation).

---

## 6. Failure Handling & Graceful Termination

Scanner faults must be contained to a single job and must not impact platform stability.

| Failure mode | Detection | Handling | Recovery |
| :--- | :--- | :--- | :--- |
| Container OOM | cgroups + exit code | Job marked FAILED, OOM event logged | Job re-queued within retry budget; dead-letter after max attempts |
| Hung socket / slow target | Read/connection timeouts + hard deadline | Container killed at deadline; job FAILED or TIMED_OUT | Job re-queued or reassigned |
| Scanner crash (non-zero exit) | Exit code != 0 | stderr captured; job FAILED | Job re-queued within retry budget |
| Adapter returns invalid findings | Schema validation failure | Findings rejected; job not completed | Job FAILED with validation reason |
| Worker process crash | Missing heartbeat | `ReapStalled` marks job FAILED after lease expiry | Job re-queued to healthy worker |
| Broker outage | Dequeue error | Daemon pauses and retries with backoff | Jobs retained; resume on recovery |
| Job cancellation | Queue `CANCELLED` state | Container killed; delivery acked | No further processing |

Graceful termination:

1. The worker supervisor wraps adapter execution in a context with timeout = `hard_execution_deadline_seconds`.
2. On context cancellation (deadline, shutdown signal, or job cancel), the supervisor sends `SIGTERM` to the container, then `SIGKILL` after a grace period.
3. The container is removed (read-only rootfs + ephemeral /tmp discarded), ensuring no residual state.
4. The job state machine transitions atomically (QUEUED → … → terminal) via `Store.Transition`; a crashed worker leaves the job in `RUNNING` until `ReapStalled` expires its lease.
5. Heartbeats are emitted to Redis and PostgreSQL; absence triggers reassignment.

---

## 7. Secrets Handling

* No platform credentials, database passwords, or API keys are mounted into or injected into the sandbox.
* Scanner credentials (if any) are scoped to the target and never leave the worker's egress path.
* Worker tokens (Redis) are short-lived, job-scoped, and scoped to (job, tenant, worker); they never grant control-plane access.
* The sandbox filesystem is ephemeral; no secrets persist between jobs.

---

## 8. Implementation Reference

| Artifact | Location | Purpose |
| :--- | :--- | :--- |
| Executor contract | `apps/worker/internal/sandbox/executor.go` | `Executor`, `Spec`, `Result`, `ExitError` |
| Rootless OCI runner | `apps/worker/internal/sandbox/oci.go` | Docker/Podman-compatible rootless container provisioning |
| Fake executor | `apps/worker/internal/sandbox/fake.go` | In-memory executor for unit tests (no container runtime) |
| Scanner adapter contract | `apps/worker/internal/adapters/` | `Executable`, `Task`, `Result` types |
| Worker daemon loop | `apps/worker/internal/daemon/daemon.go` | Dequeue → sandbox execute → complete/fail with deadline |
| Egress policy | `apps/worker/internal/egress/`, `packages/common/scope` | Target validation + pinned transport |
| Job state store | `apps/api/pkg/job/state.go` | `Store.Transition`, `Store.SetDeadline`, `Store.ReapStalled` |
| Finding schema | `packages/schemas/finding.v1.json` | Canonical finding wire format |

---

## 9. Traceability

| Artifact | Reference |
| :--- | :--- |
| Planning reference | `P1-28` |
| Milestone | Phase 1 — Foundation & Core Architecture |
| Blocked by | `P1-06` System Architecture; `P1-07` ADR-0005; Job Lifecycle / Job Queue / Scope Enforcement |
| Threat model | `docs/security/THREAT_MODEL.md` (T-10, T-11, T-13, T-14) |
| Sandboxing decision | `docs/architecture/decisions/ADR-0005.md` |
| System architecture | `docs/architecture/SYSTEM_ARCHITECTURE.md` |
| Scan profiles | `docs/architecture/SCAN_PROFILES.md` |
| Job lifecycle | `docs/architecture/JOB_LIFECYCLE.md` |
| Finding schema | `docs/architecture/FINDING_SCHEMA.md` |

---

*Kelvin Security Platform — Phase 1 Engineering Backlog*
