# Runbook RB-04: Emergency Credential Compromise & Secret Revocation

**Severity:** SEV-0 / SEV-1  
**Target Resolution Time:** < 15 minutes  
**Primary Responder:** Product Security Lead  

---

## 1. Symptom & Alert Triggers
- Exposure of JWT signing keys, database passwords, or AWS IAM credentials in public repositories, logs, or external disclosures.
- Detection of unauthorized administrative API calls from unknown IP addresses.

## 2. Immediate Diagnostic Steps
1. Identify the compromised secret ARN in AWS Secrets Manager:
   - `kelvin/prod/auth/jwt` (Session JWT Secret)
   - `kelvin/prod/database/app` (Database Credentials)
   - `kelvin/prod/redis/auth` (Queue Broker Password)

## 3. Emergency Revocation Procedures
- **Step 1: Rotate Database Password:**
  ```bash
  aws secretsmanager rotate-secret --secret-id kelvin/prod/database/app
  ```
- **Step 2: Emergency Invalidation of Active User Sessions (JWT Key Rollover):**
  Generate a new random 64-byte JWT secret and force-update Secrets Manager:
  ```bash
  NEW_SECRET=$(openssl rand -base64 48)
  aws secretsmanager put-secret-value --secret-id kelvin/prod/auth/jwt --secret-string "{\"jwt_secret\":\"$NEW_SECRET\",\"signing_algo\":\"HS256\"}"
  # Force all API pods to reload secret and invalidate outstanding tokens
  kubectl rollout restart deployment/prod-kelvin-api -n kelvin-prod
  ```
- **Step 3: Revoke AWS IAM Credentials:**
  Deactivate compromised IAM access keys via AWS CLI immediately.

## 4. Verification & Closure
- Verify all previous JWT tokens return HTTP 401 Unauthorized.
- Inspect AWS CloudTrail for access logs during the compromise window.
