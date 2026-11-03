# Runbook RB-06: Emergency Assessment Kill Switch & Rogue Scan Interruption

**Severity:** SEV-1  
**Target Resolution Time:** < 5 minutes  
**Primary Responder:** Incident Commander / On-Call Operations Lead  

---

## 1. Symptom & Alert Triggers
- Assessment scanner probing unauthorized third-party target hosts or out-of-scope customer infrastructure.
- High volume outbound traffic causing upstream target abuse reports or cloud provider network alerts.

## 2. Emergency Global Kill Switch
To immediately abort all active scanning executions across the entire cluster:
```bash
# Publish global kill switch signal via Redis
redis-cli -h kelvin-prod-redis.internal publish "kelvin:events:emergency_kill" "GLOBAL_ABORT_ALL"

# Force termination of all ephemeral scanner sandbox pods
kubectl delete pods -n kelvin-prod -l app.kubernetes.io/name=kelvin-scanner --grace-period=0 --force
```

## 3. Targeted Single-Assessment Kill Switch
To abort a specific assessment run ID:
```bash
# Call internal cancellation endpoint
curl -X POST https://api.kelvinsecurity.io/api/v1/assessments/<assessment_id>/cancel \
  -H "Authorization: Bearer $ADMIN_BEARER_TOKEN"
```

## 4. Post-Incident Follow-Up
- Place target IP/domain on the global platform blacklisted target registry.
- Revoke scope authorization for the originating organization.
