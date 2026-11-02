#!/usr/bin/env bash
# KELVIN Post-Restore Assessment State Reconciliation Script
# Safely marks in-flight assessment jobs as terminated to prevent duplicate scanning on restart.
set -euo pipefail

DATABASE_URL="${DATABASE_URL:-${KELVIN_DATABASE_URL:-}}"

if [ -z "$DATABASE_URL" ]; then
  echo "ERROR: DATABASE_URL or KELVIN_DATABASE_URL is required."
  exit 1
fi

echo "=========================================="
echo " Reconciling Assessment Job State Post-DR "
echo "=========================================="

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 <<EOF
BEGIN;

-- 1. Identify and transition assessments that were active during the outage
UPDATE assessments
SET
  status = 'failed',
  failure_reason = 'DISASTER_RECOVERY_ABORT: Execution interrupted by infrastructure failover.',
  completed_at = NOW()
WHERE status IN ('queued', 'running', 'in_progress');

-- 2. Clean up orphan scan locks
TRUNCATE TABLE assessment_concurrency_locks;

-- 3. Audit reconciliation outcome
SELECT count(*) AS reconciled_assessments
FROM assessments
WHERE failure_reason LIKE 'DISASTER_RECOVERY_ABORT%';

COMMIT;
EOF

echo "=========================================="
echo " State Reconciliation Successfully Completed "
echo "=========================================="
