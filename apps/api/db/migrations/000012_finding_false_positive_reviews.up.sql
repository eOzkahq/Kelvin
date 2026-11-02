-- ==============================================================================
-- Migration 000012: Finding False-Positive Review and Management (P3-17)
-- ==============================================================================

-- 1. Create finding_false_positive_reviews table
CREATE TABLE IF NOT EXISTS finding_false_positive_reviews (
  id                       uuid PRIMARY KEY,
  tenant_id                uuid NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
  finding_id               uuid NOT NULL,
  actor_id                 uuid REFERENCES users(id) ON DELETE SET NULL,
  action                   text NOT NULL CHECK (action IN (
                             'MARKED_FALSE_POSITIVE',
                             'REVERSED',
                             'REVIEW_FLAGGED'
                           )),
  justification            text NOT NULL,
  evidence_rebuttal        text,
  material_change_detected boolean NOT NULL DEFAULT false,
  metadata                 jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at               timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_fp_reviews_id_tenant UNIQUE (id, tenant_id),
  CONSTRAINT fk_fp_reviews_finding FOREIGN KEY (finding_id, tenant_id)
    REFERENCES findings(id, tenant_id) ON DELETE CASCADE
);

-- 2. Lookup indexes
CREATE INDEX IF NOT EXISTS idx_fp_reviews_finding
  ON finding_false_positive_reviews (tenant_id, finding_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_fp_reviews_action
  ON finding_false_positive_reviews (tenant_id, action, created_at DESC);
