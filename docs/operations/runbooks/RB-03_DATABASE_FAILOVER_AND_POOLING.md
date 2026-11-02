# Runbook RB-03: PostgreSQL Failover & PgBouncer Pool Recovery

**Severity:** SEV-1  
**Target Resolution Time:** < 30 minutes  
**Primary Responder:** Database Operations / Infrastructure Lead  

---

## 1. Symptom & Alert Triggers
- Prometheus alert: `DatabasePoolStarvation` (> 90% pool capacity used) or API `/readyz` returning HTTP 503.
- `FATAL: remaining connection slots are reserved for non-replication superuser connections`.

## 2. Immediate Diagnostic Steps
1. **Inspect Active PgBouncer Pools:**
   ```bash
   psql -h 127.0.0.1 -p 6432 -U pgbouncer -d pgbouncer -c "SHOW POOLS;"
   ```
2. **Inspect Long-Running Backend Queries:**
   ```bash
   psql "$DATABASE_URL" -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query, state FROM pg_stat_activity WHERE state != 'idle' ORDER BY duration DESC LIMIT 10;"
   ```

## 3. Mitigation Procedures
- **Scenario A: Unresponsive Long Query Holding Locks:**
  Terminate offending blocking backend query:
  ```sql
  SELECT pg_terminate_backend(<pid>);
  ```
- **Scenario B: PgBouncer Client Connection Spike:**
  Temporarily increase `max_client_conn` or restart pooler pods:
  ```bash
  kubectl rollout restart deployment/prod-pgbouncer -n kelvin-prod
  ```
- **Scenario C: AWS RDS Primary Hardware Failure:**
  Trigger multi-AZ failover via AWS CLI:
  ```bash
  aws rds reboot-db-instance --db-instance-identifier kelvin-prod-postgres --force-failover
  ```

## 4. Verification & Closure
- Confirm PgBouncer connection pool drops below 50% capacity.
- Verify read/write transactions succeed across all availability zones.
