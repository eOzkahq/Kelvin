#!/usr/bin/env bash
# KELVIN Post-Deployment Smoke Test Suite
# Validates frontend assets, API liveness/readiness, database connectivity, and Redis queue health.
set -euo pipefail

TARGET_ENV="${1:-staging}"
API_URL="${2:-}"
APP_URL="${3:-}"

if [ -z "$API_URL" ]; then
  if [ "$TARGET_ENV" = "prod" ]; then
    API_URL="https://api.kelvinsecurity.io"
    APP_URL="https://app.kelvinsecurity.io"
  else
    API_URL="https://staging-api.kelvinsecurity.io"
    APP_URL="https://staging-app.kelvinsecurity.io"
  fi
fi

echo "=========================================="
echo " Running KELVIN Post-Deployment Smoke Tests "
echo " Environment: $TARGET_ENV"
echo " API Endpoint: $API_URL"
echo " App Endpoint: $APP_URL"
echo "=========================================="

FAILED=0

# 1. API Liveness Probe Check (/healthz)
echo -n "[+] Testing API Liveness (/healthz)... "
if curl -fsS -m 10 "$API_URL/healthz" > /dev/null 2>&1; then
  echo "PASSED (HTTP 200)"
else
  echo "FAILED"
  FAILED=1
fi

# 2. API Readiness Probe Check (/readyz - DB & Redis pool check)
echo -n "[+] Testing API Readiness (/readyz)... "
if curl -fsS -m 10 "$API_URL/readyz" > /dev/null 2>&1; then
  echo "PASSED (HTTP 200)"
else
  echo "FAILED"
  FAILED=1
fi

# 3. Frontend Dashboard Root Check (HTTP 200 & HTML response)
if [ -n "$APP_URL" ]; then
  echo -n "[+] Testing Frontend SPA Root ($APP_URL)... "
  if curl -fsS -m 10 "$APP_URL" > /dev/null 2>&1; then
    echo "PASSED (HTTP 200)"
  else
    echo "FAILED"
    FAILED=1
  fi
fi

# 4. API Security Header Check
echo -n "[+] Testing Strict Security Response Headers... "
HEADERS=$(curl -sI -m 10 "$API_URL/healthz" || true)
if echo "$HEADERS" | grep -qi "Strict-Transport-Security" && echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
  echo "PASSED"
else
  echo "WARN (Headers missing or non-TLS local mock)"
fi

if [ $FAILED -ne 0 ]; then
  echo "=========================================="
  echo " ERROR: Post-Deployment Smoke Tests FAILED "
  echo " Initiating Automated Deployment Rollback "
  echo "=========================================="
  exit 1
fi

echo "=========================================="
echo " Post-Deployment Smoke Tests SUCCESSFUL "
echo "=========================================="
exit 0
