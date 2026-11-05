# KELVIN Operations — Queue Failure & DLQ Recovery Runbook

## 1. Overview & DLQ Architecture

When an assessment job encounters unexpected scanner crashes, timeouts, or unrecoverable external dependency errors, KELVIN's worker daemon invokes exponential backoff retry.
If a job exceeds its maximum attempt threshold (`max_attempts`), it is routed to the **Dead-Letter Queue (DLQ)** stream:
`kelvin:jobs:dlq`

This isolates poison-pill jobs without halting healthy queue processing for other tenants.

---

## 2. Inspecting the Dead-Letter Queue

To inspect failed jobs in the DLQ:

```bash
# Query the 10 most recent failed jobs from the Redis stream
redis-cli -a <SECRET> XREVRANGE kelvin:jobs:dlq + - COUNT 10
```

Each entry contains:
- `job_id`: Unique identifier of the failed assessment job.
- `tenant_id`: Tenant scope.
- `failed_at`: RFC3339 timestamp of failure.
- `last_error`: Root-cause error message.
- `payload`: Serialized message payload.

---

## 3. Re-Driving Failed Jobs

Once the root cause (e.g. temporary network partition or upstream rate limit) is resolved, operators can re-drive jobs back to the active queue:

### 3.1 Using the CLI Re-Drive Tool
```bash
# Re-drive specific job by ID
kelvin-admin queue redrive --job-id="<JOB_ID>" --target-queue="kelvin:jobs:assessment"

# Re-drive all jobs failed within a specific time window
kelvin-admin queue redrive --all --since="2h"
```

### 3.2 Purging Corrupted Entries
If a job was caused by a malformed payload or deleted target that cannot be processed:
```bash
# Delete entry from the DLQ stream
redis-cli -a <SECRET> XDEL kelvin:jobs:dlq "<STREAM_ENTRY_ID>"
```
