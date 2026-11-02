#!/usr/bin/env bash
# KELVIN Infrastructure as Code Validation Script
set -euo pipefail

echo "=========================================="
echo " Validating KELVIN Infrastructure as Code "
echo "=========================================="

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../infra/terraform" && pwd)"

echo "Checking Terraform structure in: $INFRA_DIR"

MODULES=("networking" "security" "database" "broker" "storage" "compute" "ingress")
for mod in "${MODULES[@]}"; do
  mod_path="$INFRA_DIR/modules/$mod"
  if [ ! -d "$mod_path" ]; then
    echo "ERROR: Module missing: $mod_path"
    exit 1
  fi
  if [ ! -f "$mod_path/main.tf" ] || [ ! -f "$mod_path/variables.tf" ] || [ ! -f "$mod_path/outputs.tf" ]; then
    echo "ERROR: Incomplete files in module: $mod"
    exit 1
  fi
  echo " Module OK: $mod"
done

ENVIRONMENTS=("dev" "staging" "prod")
for env in "${ENVIRONMENTS[@]}"; do
  env_path="$INFRA_DIR/environments/$env"
  if [ ! -d "$env_path" ]; then
    echo "ERROR: Environment missing: $env_path"
    exit 1
  fi
  if [ ! -f "$env_path/main.tf" ] || [ ! -f "$env_path/variables.tf" ] || [ ! -f "$env_path/outputs.tf" ]; then
    echo "ERROR: Incomplete files in environment: $env"
    exit 1
  fi
  echo " Environment OK: $env"
done

# Secret scanning check for .tf files
echo "Scanning for plaintext hardcoded credentials..."
if grep -rnEi "(password\s*=\s*\"[^\$]|secret_key\s*=\s*\"[^\$]|aws_secret_access_key\s*=\s*\"[^\$])" "$INFRA_DIR" --exclude="*.example"; then
  echo "ERROR: Potential hardcoded secret found!"
  exit 1
fi

echo "=========================================="
echo " Infrastructure as Code Validation Passed "
echo "=========================================="
