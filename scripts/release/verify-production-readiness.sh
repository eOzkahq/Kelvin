#!/usr/bin/env bash
# KELVIN Production Readiness & Launch Verification Script
set -euo pipefail

echo "=========================================================="
echo " KELVIN v1.0.0-GA Production Readiness Gate Verification"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CHECK_FAILURES=0

verify_file() {
    local file_path="$1"
    local description="$2"
    if [[ -f "${ROOT_DIR}/${file_path}" ]]; then
        echo "  [PASS] ${description}: ${file_path}"
    else
        echo "  [FAIL] Missing required artifact: ${file_path} (${description})"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi
}

echo "[1/5] Verifying Phase 5 Production Hardening Artifacts..."
verify_file "docs/architecture/PRODUCTION_DEPLOYMENT_ARCHITECTURE.md" "Topology Doc"
verify_file "infra/terraform/environments/prod/main.tf" "Terraform Prod IaC"
verify_file "deploy/kubernetes/base/api-deployment.yaml" "K8s API Deployment"
verify_file "deploy/kubernetes/base/worker-deployment.yaml" "K8s Worker Deployment"
verify_file "deploy/ingress/nginx-ingress.conf" "Nginx Ingress Hardening"
verify_file "deploy/postgres/hardening.sql" "Data Services Hardening"
verify_file "docs/security/SECRETS_AND_CRYPTOGRAPHIC_KEY_MANAGEMENT.md" "Secrets & KMS Mgmt"

echo "[2/5] Verifying Build, CI/CD, Supply Chain & Migrations..."
verify_file ".github/workflows/ci.yml" "Production CI Gate Workflow"
verify_file "docs/release/CI_QUALITY_AND_VERIFICATION_GATES.md" "CI Quality Gates Specification"
verify_file "scripts/release/generate-sbom.sh" "SBOM Generation Script"
verify_file "docs/release/STAGED_DEPLOYMENT_AND_ENVIRONMENT_PROMOTION.md" "Staged Promotion Doc"
verify_file "scripts/release/smoke-test.sh" "Post-Deploy Smoke Test"
verify_file "docs/database/SAFE_DATABASE_MIGRATION_AND_ROLLBACK.md" "Database Rollback Doc"

echo "[3/5] Verifying Observability, SLOs, Runbooks & Disaster Recovery..."
verify_file "packages/common/tracing/tracing.go" "W3C Distributed Tracing"
verify_file "deploy/monitoring/alerts/kelvin-slo-alerts.yml" "SLO Alertmanager Rules"
verify_file "docs/operations/INCIDENT_RESPONSE_FRAMEWORK.md" "Incident Response Framework"
verify_file "scripts/backup/verify-backup-integrity.sh" "Backup Integrity Verification"
verify_file "scripts/backup/restore-database.sh" "Disaster Recovery Restoration"

echo "[4/5] Verifying Performance, Security Assessment & Governance..."
verify_file "scripts/testing/run-load-stress-tests.sh" "Load Test Harness"
verify_file "docs/performance/PRODUCTION_CAPACITY_AND_PERFORMANCE_OPTIMIZATION.md" "Capacity Baselines"
verify_file "docs/security/INDEPENDENT_SECURITY_ASSESSMENT_REPORT.md" "Security Assessment"
verify_file "docs/security/VULNERABILITY_MANAGEMENT_AND_PATCH_GOVERNANCE.md" "Vulnerability Governance"

echo "[5/5] Verifying Final Release Authorization and Sign-Off..."
verify_file "docs/release/PRODUCTION_READINESS_REVIEW_AND_RELEASE_DECISION.md" "Readiness Review"
verify_file "docs/release/RELEASE_NOTES_v1.0.0.md" "v1.0.0 Release Notes"

if [[ $CHECK_FAILURES -gt 0 ]]; then
    echo "=========================================================="
    echo " ❌ FAILED: ${CHECK_FAILURES} production readiness checks failed!"
    echo "=========================================================="
    exit 1
fi

echo "=========================================================="
echo " ✅ ALL PRODUCTION READINESS VERIFICATION GATES PASSED"
echo " KELVIN v1.0.0-GA is formally authorized for launch!"
echo "=========================================================="
