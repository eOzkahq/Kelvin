# KELVIN Staging Environment & Secret Configuration Specification (PRE-09)

## 1. System Requirements (Oracle Linux ARM64)

The staging environment is designed to execute on an **Oracle Cloud Infrastructure (OCI) Ampere A1 Compute Instance** running **Oracle Linux 9.8 (ARM64 / aarch64)**:
- **Processor**: 1 OCPU (Ampere Altra 3.0 GHz ARM64, 2 vCPUs)
- **Memory**: Approximately 5.5 GiB physical RAM + 4 GiB swap
- **Disk**: 30 GB Root Filesystem
- **Container Engine**: Docker Engine 24+ and Docker Compose v2+ installed
- **OS Hardening & Security**: SELinux in enforcing mode, non-root user execution (UID `10001:10001`), firewalld active (SSH is currently the only permitted ingress service)
- **Host CA Bundle Path**: `/etc/pki/tls/certs/ca-bundle.crt` (Oracle Linux system root certificates)

---

## 2. Required Environment Variables & Secrets Reference

All staging runtime variables must be supplied via a secure environment file (e.g. `/etc/kelvin/staging.env` protected with `chmod 0600` owned by `root:root` or `opc:opc`) or cloud secret manager.

| Environment Variable | Description | Staging Validation Rule | Example Value |
| :--- | :--- | :--- | :--- |
| `KELVIN_ENV` | Runtime environment tier | Must be `staging` | `staging` |
| `KELVIN_API_ADDR` | API Gateway listen address | Loopback interface | `:8080` |
| `KELVIN_DATABASE_URL` | PostgreSQL connection string | Strictly requires `sslmode=verify-full` | `postgresql://postgres:pw@db.ref.supabase.co:5432/postgres?sslmode=verify-full` |
| `SUPABASE_CA_CERT_PATH`| Path to Root CA certificate | File must exist and be readable on host | `/etc/pki/tls/certs/ca-bundle.crt` |
| `KELVIN_DATABASE_MAX_CONNS`| Max DB pool connections | Default `5` in staging | `5` |
| `KELVIN_DATABASE_MIN_CONNS`| Min DB pool connections | Default `1` in staging | `1` |
| `REDIS_URL` | Redis broker connection URL | Must use TLS (`rediss://`) | `rediss://default:secret@redis-staging.cloud:6379/0` |
| `REDIS_PASSWORD` | Redis authentication password | Required | `a-strong-redis-cluster-password` |
| `REDIS_TLS_ENABLED` | Explicit Redis TLS toggle | Must be `true` | `true` |
| `KELVIN_JWT_SECRET` | Tenant auth signing secret | Min 32 bytes; no placeholders | `staging-jwt-auth-secret-min-32-chars-long!` |
| `KELVIN_EVIDENCE_SIGNING_KEY`| Evidence signed URL HMAC key | Min 32 bytes; no placeholders | `staging-evidence-hmac-key-min-32-chars-long!` |
| `SUPABASE_URL` | Supabase API endpoint | HTTPS scheme; no placeholders | `https://xyzproject.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase privileged service key| Min 20 chars; no placeholders | `eyJhbGciOi...` (Supabase service key) |
| `SUPABASE_STORAGE_BUCKET_REPORTS`| Reports storage bucket | Private bucket | `kelvin-reports` |
| `SUPABASE_STORAGE_BUCKET_EVIDENCE`| Evidence artifacts bucket | Private bucket | `kelvin-evidence` |
| `KELVIN_API_ALLOWED_ORIGINS`| CORS allowed origins | Explicit domains; no `*` | `https://staging.kelvin.security,https://eozka.com` |

---

## 3. Database TLS & CA Propagation Policy

### 3.1 Strict PostgreSQL TLS Enforcement
Both `apps/api` and `apps/worker` enforce verified database TLS in staging and production:
- The connection string must contain query parameter `sslmode=verify-full`.
- All other values (`disable`, `allow`, `prefer`, `require`, `verify-ca`, or omitted) are **strictly rejected at startup**.
- Validation errors redact database credentials to prevent credential exposure in log streams.

### 3.2 Custom CA Certificate Propagation
- When `SUPABASE_CA_CERT_PATH` or `KELVIN_DATABASE_SSL_ROOT_CERT` is configured, the certificate file is validated for readability and loaded into the `pgxpool.Config` TLS configuration (`RootCAs`).
- System trust is preserved by appending custom certificates to `x509.SystemCertPool()`, allowing validation against both public CAs and custom self-signed Supabase certificates.
- Certificate conflict detection ensures that if `sslrootcert` is present in the database URL and `KELVIN_DATABASE_SSL_ROOT_CERT` is set in the environment, they must point to the identical file path.

---

## 4. Managed Redis TLS Configuration

Managed Redis (such as Upstash, Redis Cloud, or Oracle Managed Redis) requires TLS 1.2+ encryption:
- Prefix connection strings with `rediss://` (double 's' indicates TLS).
- If using `KELVIN_REDIS_ADDR`, ensure `REDIS_TLS_ENABLED=true` is set. Plaintext Redis (`redis://` or `REDIS_TLS_ENABLED=false`) is **strictly rejected** in staging and production.
- Connection pools in staging are restricted to `5` connections for API and `3` for Worker to stay well within managed broker limits and host memory bounds.

---

## 5. Secret File Permissions & Operational Discipline

To protect secrets on the Oracle host:
```bash
# 1. Create directory and staging environment file
sudo mkdir -p /etc/kelvin
sudo touch /etc/kelvin/staging.env

# 2. Restrict permissions to root or current operator
sudo chown root:root /etc/kelvin/staging.env
sudo chmod 0600 /etc/kelvin/staging.env
```

---

## 6. Code/Build Validation vs. Live Infrastructure Connectivity

> [!IMPORTANT]
> **Validation Scope Distinction:**
> - **Code & Build Verification (Completed)**: Verifies parser rules, configuration constraints, table-driven TLS rejection, binary compilation, Docker Compose syntax, and sandbox isolation.
> - **Live Infrastructure Connectivity (Pending Live Staging Gate)**: Involves actual network socket connection to external Supabase PostgreSQL, Supabase Storage endpoints, and managed Redis over public/VPC networks.
> - Automated CI and release test runs intentionally **do not** connect to external cloud services or execute live migrations. Live connectivity validation occurs strictly during controlled operator staging deployment.
| `SUPABASE_URL` | Supabase API endpoint | HTTPS scheme; no placeholders | `https://xyzproject.supabase.co` |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase privileged service key| Min 20 chars; no placeholders | `eyJhbGciOi...` (Supabase service key) |
| `SUPABASE_STORAGE_BUCKET_REPORTS`| Reports storage bucket | Private bucket | `kelvin-reports` |
| `SUPABASE_STORAGE_BUCKET_EVIDENCE`| Evidence artifacts bucket | Private bucket | `kelvin-evidence` |
| `KELVIN_API_ALLOWED_ORIGINS`| CORS allowed origins | Explicit domains; no `*` | `https://staging.kelvin.security,https://eozka.com` |

---

## 3. Managed Redis TLS Configuration

Managed Redis (such as Upstash, Redis Cloud, or Oracle Managed Redis) requires TLS 1.2+ encryption:
- Prefix connection strings with `rediss://` (double 's' indicates TLS).
- If using `KELVIN_REDIS_ADDR`, ensure `REDIS_TLS_ENABLED=true` is set.
- Connection pools in staging are restricted to `5` connections for API and `10` for Worker to stay well within managed broker limits.

---

## 4. Supabase Private Bucket Storage Setup

KELVIN requires two dedicated private storage buckets in the staging Supabase project:

1. **`kelvin-reports`**:
   - Access level: **Private** (Public access disabled).
   - Contains generated PDF and JSON assessment reports.
   - Accessed exclusively via server-side API with `SUPABASE_SERVICE_ROLE_KEY`.

2. **`kelvin-evidence`**:
   - Access level: **Private** (Public access disabled).
   - Contains raw scan evidence artifacts (e.g., ZAP JSON, Nuclei raw logs).
   - Accessed via time-expiring HMAC signed download URLs (5-minute TTL).

---

## 5. Security & Verification Checklist

Before starting staging containers:
- [ ] Database URL contains `sslmode=verify-full`.
- [ ] Root CA certificate exists at `SUPABASE_CA_CERT_PATH`.
- [ ] No weak or default secrets are used (`KELVIN_JWT_SECRET`, `KELVIN_EVIDENCE_SIGNING_KEY`).
- [ ] `docker compose config` validates without errors.
- [ ] `/var/run/docker.sock` is NOT mounted.
- [ ] Staging API port is bound strictly to `127.0.0.1:8080:8080`.
