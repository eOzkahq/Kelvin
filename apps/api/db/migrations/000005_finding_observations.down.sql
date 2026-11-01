-- Migration 000005: Finding Observations and Correlation Groups (Down)

DROP TRIGGER IF EXISTS trg_prevent_observation_update ON finding_observations;
DROP FUNCTION IF EXISTS prevent_observation_update();
DROP TABLE IF EXISTS finding_observations CASCADE;

ALTER TABLE findings DROP COLUMN IF EXISTS correlation_group_id;
DROP TABLE IF EXISTS correlation_groups CASCADE;
