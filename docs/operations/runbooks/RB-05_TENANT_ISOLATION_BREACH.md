# Runbook RB-05: Suspected Multi-Tenant Data Isolation Breach

**Severity:** SEV-0  
**Target Resolution Time:** Immediate containment (< 15 minutes)  
**Primary Responder:** Product Security Lead & Executive Incident Commander  

---

## 1. Symptom & Alert Triggers
- Security alert or customer report indicating that an organization or user was able to observe findings, targets, or assets belonging to a different tenant.
- Audit log anomaly showing Row-Level Security (RLS) bypass.

## 2. Immediate Containment Steps
1. **Isolate Affected Tenant:**
   Temporarily disable tenant access via administrative toggle:
   ```bash
   psql "$DATABASE_URL" -c "UPDATE organizations SET status = 'suspended' WHERE id = '<compromised_org_id>';"
   ```
2. **Freeze Assessment Execution for Affected Scope:**
   Cancel any active scan executions belonging to the tenant.
3. **Capture Forensic Evidence Snapshot:**
   Export immutable audit logs and database transaction logs for the incident timeframe before making any code modifications.

## 3. Investigation & Remediation
- Review API handler context propagation: verify `kelvin.tenant_id` session variable is strictly bound on all PostgreSQL connections.
- Inspect whether caching layers accidentally shared cross-tenant keys.
- Draft mandatory breach notification in coordination with Legal and Compliance teams within statutory timelines (GDPR 72-hour window).

## 4. Verification & Post-Mortem
- Confirm RLS policies prevent cross-tenant queries under automated regression suites.
- Convene mandatory SEV-0 Post-Incident Review.
