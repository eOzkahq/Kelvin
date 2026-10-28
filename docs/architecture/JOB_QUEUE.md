# Assessment Job Queue

The API producer and worker consumer share `packages/common/queue.IJobQueue`. Business logic can depend on that contract without importing Redis code. `NewRedis` provides the Redis Streams adapter; `NewMemory` provides a fast in-memory adapter for tests and local use.

Messages use the `job-message.v1.json` contract embedded by `packages/schemas`: UUID identifiers, a wire enum task type, bounded retry count, and an object payload. `Message.Validate` rejects malformed input at enqueue and consume time. Malformed stream entries are acknowledged into the isolated `<prefix>:dlq` stream rather than returned to the worker loop.

Redis uses a consumer group, pending-entry reclaim after worker loss, per-job status hashes, Redis TTL heartbeats, and a delayed sorted set for retries. Retry delay is exponential (`base × 2^(attempt-1)`); after `max_attempts`, the message and failure reason are routed to the DLQ. `GetStatus` reports queue-side state; PostgreSQL remains authoritative for lifecycle state and reconciliation (ADR-0002/0003).

Configure `RedisConfig.TokenSecret` with at least 32 random bytes and set `WorkerID` to issue short-lived HMAC worker tokens scoped to the job and worker. When token signing is enabled, consumption verifies the signature, scope, and expiry before yielding work. Never log or expose token values.

Redis must be deployed with ADR-0003 persistence, TLS, ACLs, and `noeviction`. The queue package expects the caller to configure the Redis client with those transport and access controls.

The Redis lifecycle integration test uses a disposable Redis 7 instance: start it with `docker compose up -d redis`, set `KELVIN_REDIS_ADDR=localhost:6379` and `KELVIN_REDIS_PASSWORD` to match the Compose secret, then run `go test ./queue` from `packages/common`.
