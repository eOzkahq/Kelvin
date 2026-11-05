# KELVIN Deployment — Production Configuration Guide

## 1. Environment Variable Reference

The table below documents all environment variables required to operate KELVIN with Redis 7+ and Supabase in production:

| Variable | Description | Production Default / Example | Sensitive |
| :--- | :--- | :--- | :--- |
| `REDIS_URL` | Redis 7+ connection URL with TLS | `rediss://default:<SECRET>@redis.prod:6380/0` | **Yes** |
| `REDIS_POOL_SIZE` | Max pooled connections | `50` | No |
| `REDIS_MIN_IDLE_CONNS` | Min idle connections | `10` | No |
| `REDIS_DIAL_TIMEOUT` | Dial timeout duration | `5s` | No |
| `REDIS_READ_TIMEOUT` | Read timeout duration | `3s` | No |
| `REDIS_WRITE_TIMEOUT` | Write timeout duration | `3s` | No |
| `REDIS_TLS_ENABLED` | Enforce TLS 1.2+ encryption | `true` | No |
| `SUPABASE_URL` | Base REST API URL | `https://<ref>.supabase.co` | No |
| `SUPABASE_ANON_KEY` | Public anon key | `eyJ...` | No |
| `SUPABASE_SERVICE_ROLE_KEY` | Privileged service role key | `eyJ...` | **Yes** |
| `SUPABASE_DB_HOST` | Database hostname | `db.<ref>.supabase.co` | No |
| `SUPABASE_DB_PORT` | Database port | `5432` | No |
| `SUPABASE_DB_NAME` | Database catalog name | `postgres` | No |
| `SUPABASE_DB_USER` | Database role user | `postgres` | No |
| `SUPABASE_DB_PASSWORD` | Database role password | `<STRONG_SECRET>` | **Yes** |
| `SUPABASE_DB_SSLMODE` | SSL certificate enforcement | `verify-full` | No |
| `SUPABASE_DB_MAX_OPEN_CONNS` | Connection pool ceiling | `25` | No |
| `SUPABASE_DB_MAX_IDLE_CONNS` | Connection pool idle conns | `5` | No |
| `SUPABASE_STORAGE_BUCKET_REPORTS` | Private reports bucket | `kelvin-reports-private` | No |
| `SUPABASE_STORAGE_BUCKET_EVIDENCE` | Private evidence bucket | `kelvin-evidence-private` | No |
| `SUPABASE_STORAGE_SIGNED_URL_EXPIRY`| Max TTL for signed links | `300s` | No |

---

## 2. Security & Secrets Management Best Practices

1. **Vault / AWS Secrets Manager**: Inject sensitive secrets (`SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_DB_PASSWORD`, `REDIS_URL`) at container startup via KMS-backed environment variables or secret volumes.
2. **Network Egress**: Restrict worker and API egress traffic strictly to the Redis cluster, Supabase endpoints, and authorized scan targets.
3. **No Unencrypted Traffic**: Plain-text Redis (`redis://`) and plaintext database connections (`sslmode=disable`) are strictly rejected in production environments.
