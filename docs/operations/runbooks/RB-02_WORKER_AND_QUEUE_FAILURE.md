# Runbook RB-02: Worker Fleet Crash & Redis Queue Saturation

**Severity:** SEV-1 / SEV-2  
**Target Resolution Time:** < 45 minutes  
**Primary Responder:** Platform On-Call Engineer  

---

## 1. Symptom & Alert Triggers
- Prometheus alert: `QueueSaturation` (depth > 50) or `WorkerFleetUnhealthy` (< 2 active runners).
- Assessment scans remain in `queued` status indefinitely without progressing to `running`.

## 2. Immediate Diagnostic Steps
1. **Check Redis Broker Connectivity:**
   ```bash
   redis-cli -h kelvin-prod-redis.internal ping
   ```
2. **Inspect Current Queue Depth:**
   ```bash
   redis-cli -h kelvin-prod-redis.internal xlen kelvin:queue:assessments
   ```
3. **Inspect Worker Pod Logs:**
   ```bash
   kubectl logs -n kelvin-prod -l app.kubernetes.io/name=kelvin-worker --tail=100
   ```

## 3. Mitigation Procedures
- **Scenario A: Worker Fleet Capacity Starvation:**
  Scale worker replicas immediately:
  ```bash
  kubectl scale deployment/prod-kelvin-worker -n kelvin-prod --replicas=16
  ```
- **Scenario B: Poison Task Stalling Worker Consumer:**
  If a single corrupted assessment payload causes workers to crash on deserialization:
  Inspect the head of the stream and move the offending job ID to dead-letter queue (`kelvin:queue:deadletter`).
- **Scenario C: Redis Broker Failover:**
  If primary Redis node is unresponsive, Sentinel will automatically elect a new master. Force worker reconnection by restarting worker pods:
  ```bash
  kubectl rollout restart deployment/prod-kelvin-worker -n kelvin-prod
  ```

## 4. Verification & Closure
- Confirm queue depth reduces steadily.
- Confirm active assessment scans transition to `completed`.
