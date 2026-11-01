# Nuclei Controlled Adapter Integration

KELVIN integrates Nuclei as an external containerized scanner running in a rootless OCI sandbox under ADR-0005. To guarantee predictable, safe assessment execution and prevent arbitrary remote code or template execution, Nuclei execution is strictly governed by a controlled adapter pattern.

## Safety & Architectural Invariants

| Invariant | Implementation / Enforcement |
| --- | --- |
| **Catalog Restriction** | The template catalog is pinned to `kelvin.safe.web.v1` and verified by immutable SHA-256 digest. Unreviewed upstream template downloads (`-duc` flag enforced) and custom user template injections are prohibited. |
| **Process Invocation** | Invocation is constructed via `internal/scannerprocess/invocation.go`. Fixed entrypoint `/nuclei` with non-overridable, pinned flags: `-duc`, `-u`, `-t /opt/kelvin/templates/kelvin.safe.web.v1`, `-jsonl`, `-silent`, `-no-color`, `-rl`, `-c`, `-timeout`, and `-severity`. Arbitrary flags or user commands are rejected. |
| **Configuration Schema** | Scanner settings are validated against `ScannerConfigV1` with `nuclei` schema. Severity allowlist is restricted to `info`, `low`, `medium`, `high`, and `critical` without duplicates. Concurrency and rate limits cannot exceed adapter or profile budgets. |
| **Execution Isolation** | Runs as non-root user `UID 10001:10001`, dropped capabilities (`ALL`), read-only rootfs, no exec tmpfs mounts, bounded memory (512MB) and CPU (2 cores), with pids limit (64). |
| **Output Normalization** | Raw JSONL stream is parsed line-by-line and converted into Kelvin's Canonical Finding Schema (`finding.v1.json`). Target asset identity is derived strictly from the validated worker Task context, preventing untrusted scanner-reported hosts or sensitive query strings from escaping into the findings database. |
| **Cancellation & Timeouts** | Adapter implements the full `ScannerAdapter` lifecycle including context cancellation and execution deadlines. |

## Release Gates

`deploy/scanners/images.lock.json` contains `status: not-released` with null digests for the Nuclei container image and `kelvin.safe.web.v1` template catalog. Registry policy (`validateVersionPolicy`) requires an immutable digest and matching pinned image reference. Production deployment requires building and signing the runtime container image before enabling live assessments.
