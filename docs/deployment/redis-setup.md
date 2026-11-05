# KELVIN Deployment — Redis 7+ Setup Guide

## 1. Prerequisites & Version Requirements

- **Engine**: Redis 7.0 or higher.
- **Persistence**: Append-Only File (AOF) enabled (`appendonly yes`, `appendfsync everysec`).
- **Memory Management**: Explicit `maxmemory` ceiling with `noeviction` policy to prevent queue message drops.
- **Network**: Private VPC subnet or TLS-encrypted network transit.

---

## 2. Local & Development Setup (Docker Compose)

The local development stack includes Redis 7 automatically configured in `docker-compose.yml`:

```bash
# Start Redis 7 service
docker compose up -d redis

# Verify Redis health
docker compose exec redis redis-cli -a kelvin_redis_dev_secret ping
# Expected output: PONG
```

---

## 3. Production Managed Deployment (AWS ElastiCache / Redis Cloud)

### 3.1 Recommended Production Sizing
- **Node Type**: Minimum 2-node cluster with automated failover (Primary + Replica).
- **RAM**: Minimum 4 GB RAM per node for high-throughput scanning.
- **Engine Version**: Redis 7.2+.

### 3.2 Security Hardening Checklist
- [x] Enable in-transit TLS encryption (`rediss://`).
- [x] Set strong authentication password via `requirepass` or ACL user.
- [x] Bind only to private VPC interfaces (never expose port 6379 to the internet).
- [x] Restrict dangerous commands (`FLUSHALL`, `FLUSHDB`, `CONFIG`, `KEYS`) using `rename-command` or Redis ACLs.

### 3.3 Redis Configuration Directives (`redis.conf`)
```ini
# Persistence
appendonly yes
appendfsync everysec
no-appendfsync-on-rewrite no
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb

# Memory management
maxmemory 2gb
maxmemory-policy noeviction

# Networking & Security
protected-mode yes
timeout 300
tcp-keepalive 300
```
