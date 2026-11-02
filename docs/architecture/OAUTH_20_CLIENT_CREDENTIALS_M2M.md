# OAuth 2.0 Client Credentials for Machine-to-Machine Access Architecture

## 1. Overview
The OAuth 2.0 Client Credentials subsystem implements the standard RFC 6749 machine-to-machine profile for enterprise automation, CI/CD runners, and integration workers. It issues short-lived, cryptographically signed Bearer JWTs bound strictly to registered Service Account permissions, enforcing anti-scope escalation guards and immediate revocation controls.

## 2. Token Lifecycle & Authentication Sequence

```mermaid
sequenceDiagram
    participant CI as CI/CD Pipeline / Service Client
    participant OAuthServer as Kelvin OAuth Token Endpoint
    participant ProtectedAPI as Kelvin Protected API

    CI->>OAuthServer: POST /oauth/token (grant_type=client_credentials, client_id, client_secret, scope)
    OAuthServer->>OAuthServer: Authenticate Client ID & SHA-256 Secret Hash
    OAuthServer->>OAuthServer: Check Account Active (Reject if SUSPENDED or REVOKED)
    OAuthServer->>OAuthServer: Verify Scopes <= Service Account Permissions
    OAuthServer-->>CI: 200 OK { access_token (JWT), token_type: 'Bearer', expires_in: 3600 }

    CI->>ProtectedAPI: GET /api/v1/assessments (Authorization: Bearer <jwt>)
    ProtectedAPI->>ProtectedAPI: Verify HMAC-SHA256 Signature & Expiry (< 1 hour)
    ProtectedAPI->>ProtectedAPI: Verify Token Not in Revocation Store
    ProtectedAPI->>ProtectedAPI: Enforce Required Scope (e.g. scans:read)
    ProtectedAPI-->>CI: 200 OK (Protected Resource Response)
```

## 3. Key Architectural Guarantees
1. **RFC 6749 Client Credentials Profile**: Exchanges `client_id` and `client_secret` via `grant_type=client_credentials` for scoped access tokens. User-delegated authorization flows (e.g., authorization code with user redirect) are decoupled.
2. **Strict Anti-Scope Escalation**: Requested scopes must be a strict subset of the permissions assigned to the underlying Service Account identity. Requests containing ungranted scopes fail with `ErrScopeEscalationDenied`.
3. **Bounded 1-Hour Token Lifetime**: Tokens expire automatically after 3600 seconds (`expires_in = 3600`), minimizing risk windows for leaked tokens.
4. **Immediate Revocation and Cascading Invalidation**: Tokens are tracked via unique IDs (`jti`). Individual tokens can be revoked on-demand. Suspending or revoking the service account immediately invalidates all active tokens issued to it.
5. **Decoupled Identity and Secrets**: Tokens convey claims (`sub`, `org_id`, `scopes`) without embedding credentials or secrets.
