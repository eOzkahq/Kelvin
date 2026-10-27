-- Kelvin Security Platform — Development Seed Data
-- Provisions a mock tenant, administrative and analyst users, a sample project,
-- and default scan profiles for local development and integration tests.

-- 1. Mock Tenant
INSERT INTO tenants (id, name, slug, status, settings)
VALUES (
  '11111111-1111-7000-8000-000000000001'::uuid,
  'Acme Defense Corp',
  'acme-defense',
  'ACTIVE',
  '{"retention_days": 90, "max_concurrent_scans": 5}'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- 2. Mock Users
INSERT INTO users (id, tenant_id, email, display_name, role, is_active)
VALUES 
  (
    '22222222-2222-7000-8000-000000000001'::uuid,
    '11111111-1111-7000-8000-000000000001'::uuid,
    'admin@acme.internal',
    'Acme Admin',
    'TENANT_ADMIN',
    true
  ),
  (
    '22222222-2222-7000-8000-000000000002'::uuid,
    '11111111-1111-7000-8000-000000000001'::uuid,
    'analyst@acme.internal',
    'Junior Security Analyst',
    'SECURITY_ANALYST',
    true
  )
ON CONFLICT (id) DO NOTHING;

-- 3. Mock Project
INSERT INTO projects (id, tenant_id, name, description, scope_boundaries)
VALUES (
  '33333333-3333-7000-8000-000000000001'::uuid,
  '11111111-1111-7000-8000-000000000001'::uuid,
  'Production Perimeter & External API',
  'Primary public facing endpoints and corporate API gateways',
  '{"allow": ["mock-target.local", "127.0.0.1/32"], "deny": ["169.254.169.254/32", "10.0.0.0/8"]}'::jsonb
) ON CONFLICT (id) DO NOTHING;

-- 4. Mock Asset
INSERT INTO assets (id, tenant_id, project_id, target_type, value, is_verified, verification_method, verified_at)
VALUES (
  '44444444-4444-7000-8000-000000000001'::uuid,
  '11111111-1111-7000-8000-000000000001'::uuid,
  '33333333-3333-7000-8000-000000000001'::uuid,
  'URL',
  'http://localhost:8081',
  true,
  'HTTP_WELL_KNOWN',
  now()
) ON CONFLICT (id) DO NOTHING;

-- 5. Built-in Scan Profile (Standard Baseline)
INSERT INTO scan_profiles (id, tenant_id, profile_id, version, definition, status)
VALUES (
  '55555555-5555-7000-8000-000000000001'::uuid,
  NULL, -- Global built-in profile
  'kelvin.profile.standard',
  '1.0.0',
  '{
    "name": "Standard Vulnerability & Port Baseline",
    "scanners": [
      {"name": "nmap", "args": ["-sV", "--top-ports", "1000"]},
      {"name": "nuclei", "args": ["-tags", "cve,misconfig"]}
    ],
    "timeout_seconds": 3600
  }'::jsonb,
  'ACTIVE'
) ON CONFLICT (id) DO NOTHING;

