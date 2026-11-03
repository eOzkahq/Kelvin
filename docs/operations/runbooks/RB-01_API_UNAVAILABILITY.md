# Runbook RB-01: API Unavailability & High Latency Triage

**Severity:** SEV-1  
**Target Resolution Time:** < 30 minutes  
**Primary Responder:** Platform On-Call Engineer  

---

## 1. Symptom & Alert Triggers
- Prometheus alert: `APIHighErrorRate` (5xx > 1%) or `APIHighLatency` (p95 > 250ms).
- Users report HTTP 502 Bad Gateway or 503 Service Unavailable errors.

## 2. Immediate Diagnostic Steps
1. **Check Pod Status in Kubernetes:**
   ```bash
   kubectl get pods -n kelvin-prod -l app.kubernetes.io/name=kelvin-api
   ```
2. **Inspect Container Logs for Panics / OOMs:**
   ```bash
   kubectl logs -n kelvin-prod -l app.kubernetes.io/name=kelvin-api --tail=100 --prefix
   ```
3. **Verify Database Readiness Endpoint:**
   ```bash
   curl -i https://api.kelvinsecurity.io/readyz
   ```

## 3. Mitigation Procedures
- **Scenario A: Pod CrashLoopBackOff due to Memory Pressure:**
  Temporarily scale HPA minimum replicas:
  ```bash
  kubectl scale deployment/prod-kelvin-api -n kelvin-prod --replicas=12
  ```
- **Scenario B: Upstream Database Exhaustion:**
  Follow [RB-03](RB-03_DATABASE_FAILOVER_AND_POOLING.md) to inspect PgBouncer connection pool.
- **Scenario C: Bad Deployment Rollout:**
  Execute immediate rollback to previous replica:
  ```bash
  kubectl rollout undo deployment/prod-kelvin-api -n kelvin-prod
  ```

## 4. Verification & Closure
- Confirm `/healthz` and `/readyz` return HTTP 200.
- Verify error rate drops below 0.1% on Grafana overview dashboard.
