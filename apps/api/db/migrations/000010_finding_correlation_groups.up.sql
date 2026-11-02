-- ==============================================================================
-- Migration 000010: Finding Correlation Group Model (P3-14)
-- ==============================================================================

-- 1. Create finding_correlation_groups table
CREATE TABLE IF NOT EXISTS finding_correlation_groups (
  id               uuid PRIMARY KEY,
  tenant_id        uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  name             text NOT NULL,
  correlation_type text NOT NULL CHECK (correlation_type IN (
                     'SHARED_VULNERABILITY_CLASS',
                     'SAME_TARGET_CLUSTER',
                     'COMMON_IDENTIFIER',
                     'ANALYST_CURATED'
                   )),
  description      text,
  rule_pattern     text,
  metadata         jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_correlation_groups_id_tenant UNIQUE (id, tenant_id)
);

-- 2. Create finding_correlation_group_members table
CREATE TABLE IF NOT EXISTS finding_correlation_group_members (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  group_id   uuid NOT NULL,
  finding_id uuid NOT NULL,
  added_by   uuid REFERENCES users(id) ON DELETE SET NULL,
  reason     text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_group_members_group_finding UNIQUE (group_id, finding_id),
  CONSTRAINT uq_group_members_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT fk_group_members_group FOREIGN KEY (group_id, tenant_id)
    REFERENCES finding_correlation_groups(id, tenant_id) ON DELETE CASCADE,
  CONSTRAINT fk_group_members_finding FOREIGN KEY (finding_id, tenant_id)
    REFERENCES findings(id, tenant_id) ON DELETE CASCADE
);

-- 3. Lookup indexes for tenant-scoped group and finding queries
CREATE INDEX IF NOT EXISTS idx_group_members_group_lookup
  ON finding_correlation_group_members (tenant_id, group_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_group_members_finding_lookup
  ON finding_correlation_group_members (tenant_id, finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_correlation_groups_tenant_type
  ON finding_correlation_groups (tenant_id, correlation_type, created_at DESC);
