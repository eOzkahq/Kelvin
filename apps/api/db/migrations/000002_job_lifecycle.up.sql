ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check CHECK
  (status IN ('QUEUED','VALIDATING','RUNNING','COMPLETED','FAILED','TIMED_OUT','CANCELLED'));
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS hard_deadline_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS queued_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS idx_jobs_hard_deadline
  ON jobs (hard_deadline_at) WHERE status = 'RUNNING';

ALTER TABLE assessments DROP CONSTRAINT IF EXISTS assessments_status_check;
ALTER TABLE assessments ADD CONSTRAINT assessments_status_check CHECK
  (status IN ('QUEUED','VALIDATING_SCOPE','RUNNING','COMPLETED','FAILED','TIMED_OUT','CANCELLED'));
