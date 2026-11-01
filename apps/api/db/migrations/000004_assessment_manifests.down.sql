DROP TRIGGER IF EXISTS trg_prevent_manifest_update ON assessment_manifests;
DROP FUNCTION IF EXISTS enforce_assessment_manifest_immutability();
DROP TABLE IF EXISTS assessment_manifests CASCADE;
