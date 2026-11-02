-- ==============================================================================
-- Migration 000009: Immutable Finding Activity Timeline (P3-11)
-- ==============================================================================

-- 1. Create finding_activity_timeline table
CREATE TABLE IF NOT EXISTS finding_activity_timeline (
  id             uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  finding_id     uuid NOT NULL,
  actor_id       uuid REFERENCES users(id) ON DELETE SET NULL,
  event_type     text NOT NULL,
  payload        jsonb NOT NULL DEFAULT '{}'::jsonb,
  correlation_id uuid NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_finding_activity_timeline_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT fk_finding_activity_timeline_finding FOREIGN KEY (finding_id, tenant_id)
    REFERENCES findings(id, tenant_id) ON DELETE RESTRICT
);

-- 2. Performance indexes for chronological query by finding within tenant
CREATE INDEX IF NOT EXISTS idx_finding_activity_timeline_lookup
  ON finding_activity_timeline (tenant_id, finding_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_finding_activity_timeline_actor
  ON finding_activity_timeline (tenant_id, actor_id, created_at DESC)
  WHERE actor_id IS NOT NULL;

-- 3. Invariant: Append-only protection rule (prevent updates and deletions)
CREATE OR REPLACE RULE no_update_finding_activity_timeline AS
  ON UPDATE TO finding_activity_timeline DO INSTEAD NOTHING;

CREATE OR REPLACE RULE no_delete_finding_activity_timeline AS
  ON DELETE TO finding_activity_timeline DO INSTEAD NOTHING;
