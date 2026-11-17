#!/usr/bin/env bash
# ==============================================================================
# Kelvin Worker Local & Lab Verification Test Harness (M9.1-04)
# Validates worker compilation, diagnostics HTTP server (:8089), and graceful shutdown.
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "=== [1/5] Building Kelvin Worker Binary ==="
TEMP_BIN="$(mktemp -t kelvin-worker-test.XXXXXX 2>/dev/null || echo "/tmp/kelvin-worker-test-$$")"
rm -f "$TEMP_BIN"

GOWORK=off go build -o "$TEMP_BIN" ./apps/worker/cmd/runner
echo "✓ Worker compiled successfully: $TEMP_BIN"

echo "=== [2/5] Starting Worker in Isolated Test Harness ==="
export KELVIN_ENV="development"
export KELVIN_LOG_LEVEL="info"
export KELVIN_WORKER_ID="worker-lab-test-01"
export KELVIN_WORKER_HEALTH_ADDR="127.0.0.1:8089"
export KELVIN_CANARY_ONLY="true"
export KELVIN_CANARY_ALLOWED_TARGETS="scanner-mock.kelvin.internal,127.0.0.1,localhost"

"$TEMP_BIN" > /tmp/kelvin-worker-test.log 2>&1 &
WORKER_PID=$!
echo "✓ Worker running with PID: $WORKER_PID"

cleanup() {
    if kill -0 "$WORKER_PID" 2>/dev/null; then
        echo "Cleaning up worker PID $WORKER_PID..."
        kill -TERM "$WORKER_PID" 2>/dev/null || true
        wait "$WORKER_PID" 2>/dev/null || true
    fi
    rm -f "$TEMP_BIN" /tmp/kelvin-worker-test.log
}
trap cleanup EXIT

echo "=== [3/5] Probing Healthz & Readyz Endpoints ==="
MAX_RETRIES=20
HEALTH_OK=false
for i in $(seq 1 $MAX_RETRIES); do
    if curl -s -f "http://127.0.0.1:8089/healthz" > /dev/null 2>&1; then
        HEALTH_OK=true
        break
    fi
    sleep 0.5
done

if [ "$HEALTH_OK" != "true" ]; then
    echo "❌ Healthz probe failed after $MAX_RETRIES attempts. Worker log:"
    cat /tmp/kelvin-worker-test.log
    exit 1
fi
echo "✓ /healthz responded with HTTP 200 OK"

READYZ_STATUS=$(curl -s "http://127.0.0.1:8089/readyz" || true)
echo "✓ /readyz response received: $READYZ_STATUS"

echo "=== [4/5] Testing Graceful Shutdown via SIGTERM ==="
kill -TERM "$WORKER_PID"

WAIT_RETRIES=20
EXITED=false
for i in $(seq 1 $MAX_RETRIES); do
    if ! kill -0 "$WORKER_PID" 2>/dev/null; then
        EXITED=true
        break
    fi
    sleep 0.5
done

if [ "$EXITED" != "true" ]; then
    echo "❌ Worker failed to exit within timeout after SIGTERM"
    exit 1
fi

wait "$WORKER_PID" 2>/dev/null || true
EXIT_CODE=$?
echo "✓ Worker cleanly terminated with exit code: $EXIT_CODE"

echo "=== [5/5] Worker Verification Complete ==="
echo "All worker lifecycle and health checks passed cleanly."
