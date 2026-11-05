# KELVIN Operations — Backup and Recovery Runbook

## 1. Overview & RPO / RTO Targets

- **Recovery Point Objective (RPO)**: $< 15 \text{ minutes}$ for relational assessment data; $< 1 \text{ hour}$ for evidence blobs.
- **Recovery Time Objective (RTO)**: $< 30 \text{ minutes}$ for complete cluster restoration.

---

## 2. PostgreSQL / Supabase Backup Architecture

Supabase provides automated daily backups and Point-In-Time Recovery (PITR) for enterprise tiers.

### 2.1 Manual Snapshot Trigger
To take an out-of-band logical backup prior to database migrations or infrastructure changes:

```bash
pg_dump -h db.<PROJECT_REF>.supabase.co \
  -U postgres \
  -d postgres \
  --format=custom \
  --no-owner \
  --file=kelvin_backup_$(date +%Y%m%d_%H%M%S).dump
```

### 2.2 Restoration Procedure
```bash
pg_restore -h db.<PROJECT_REF>.supabase.co \
  -U postgres \
  -d postgres \
  --clean \
  --if-exists \
  kelvin_backup_<TIMESTAMP>.dump
```

---

## 3. Redis Persistence & State Snapshotting

Redis is configured with AOF (`appendonly yes`) and RDB periodic snapshots:
1. **RDB Snapshot Verification**:
   ```bash
   redis-cli -a <SECRET> LASTSAVE
   ```
2. **On-Demand Background Save**:
   ```bash
   redis-cli -a <SECRET> BGSAVE
   ```
3. **Restoration**: Copy the dump snapshot to `/data/dump.rdb` and restart the Redis service.
