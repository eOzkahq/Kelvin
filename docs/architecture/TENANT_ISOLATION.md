# Tenant Isolation and Data Access

## Tenant identity flow

The API accepts tenant identity only from a verified JWT `tid` claim. `auth.Middleware` validates the principal and places the UUID in `packages/common/tenant` context alongside the authenticated principal; request headers and resource path parameters never establish tenant identity. Platform administrators remain tenant-scoped. There is no implicit cross-tenant guard bypass.

Workers receive `tenant_id` in the validated queue envelope. The worker rejects malformed or zero tenant IDs before dispatch and reconstructs the same common tenant context for job handling. The queue's job-scoped worker token binds job, tenant, and worker IDs and is verified before a Redis delivery is returned when token signing is configured.

## Repository and transaction pattern

Every tenant-owned database operation uses `apps/api/internal/database.BeginTenantTx` or `apps/worker/internal/database.BeginTenantTx`. Both fail closed when context has no tenant, assume `kelvin_app` with `SET LOCAL ROLE`, then set `app.tenant_id` using transaction-local `set_config`; pooled connections cannot retain another request's tenant. The connecting principal must be granted membership in `kelvin_app`, and a failed role switch aborts the transaction. API repository queries should also include an explicit predicate produced by `database.TenantPredicate`, for example `f.tenant_id = $1`, and bind the returned UUID as a query argument. RLS is a second boundary, not a substitute for parent ownership checks or explicit repository predicates.

Nested reads must scope both child and parent by the same tenant or load the child through a join constrained by tenant. Nested writes are protected by composite `(resource_id, tenant_id)` foreign keys. A resource from tenant B therefore cannot be attached to a tenant A assessment, job, finding, evidence record, or report even if application code supplies mismatched IDs.

## PostgreSQL enforcement

The canonical GUC is `app.tenant_id`, consumed by `current_tenant_id()`. Each tenant table has RLS enabled and forced; absent context resolves to `NULL` and exposes no rows. `tenants` is scoped by `id = current_tenant_id()`. `scan_profiles` retains its documented global built-in rows plus tenant-owned profiles. The application role `kelvin_app` is `NOLOGIN`, has table privileges, and must be assumed by the API/worker database principal; production principals must not be superusers or `BYPASSRLS` roles. The separate `kelvin_purger` role is reserved for the audited retention pipeline.

Migration `000003_tenant_boundary` adds tenant-root RLS and composite ownership constraints for authentication sessions, jobs, findings, finding events, evidence, reports, and audit actors. Audit writes assume `kelvin_audit_writer`; its insert policy accepts either the current tenant or a global (`tenant_id IS NULL`) service event. The audit service binds tenant events to authenticated context before writing. Global audit rows are not made visible to tenant sessions by broadening tenant policies.

## Tests

Unit tests cover claim-derived context, platform-admin cross-tenant denial, safe tenant setting, explicit query predicates, worker rejection of unscoped jobs, and missing-context failure. The opt-in PostgreSQL integration test verifies tenant A cannot read or write tenant B projects and cannot attach a tenant B project to a tenant A asset. Run it with migrations applied and `KELVIN_DATABASE_URL` set to a database principal allowed to `SET ROLE kelvin_app`.
