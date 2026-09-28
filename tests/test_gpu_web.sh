#!/usr/bin/env bash
#
# End-to-end HTTP test of the GPU attestation endpoint, driven purely with
# curl(1).
#
# Endpoint taken from src/api.rs:
#
#   GET  /gpu-attestation   -> 200 {"gpu-attestation":"<script output>"}
#
# The endpoint runs gpu-attest/gpu_local_attest.sh and returns its output
# verbatim in the `gpu-attestation` field. This test checks that the response is
# a JSON object carrying exactly that field, and that the field is non-empty.
#
# Environment:
#   WEB_BASE_URL   base URL of a *running* service (default http://127.0.0.1:8000)
#   WEB_START_CMD  command that starts the service; when unset and the service
#                  is not already answering, `cargo run` is used with
#                  ROCKET_PORT derived from WEB_BASE_URL.
#
# The script exits 0 only if every check passes.

set -uo pipefail

BASE_URL="${WEB_BASE_URL:-http://127.0.0.1:8000}"
BASE_URL="${BASE_URL%/}"

# Port the service must listen on, derived from the base URL.
BASE_PORT="$(printf '%s' "$BASE_URL" | sed -n 's#.*:\([0-9]\{1,5\}\)$#\1#p')"
BASE_PORT="${BASE_PORT:-8000}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

PASS=0
FAIL=0
SERVER_PID=""

ok()   { printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
info() { printf '  [INFO] %s\n' "$1"; }

cleanup() {
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Ensure the service is up
# ---------------------------------------------------------------------------

echo "== Service bootstrap =="
echo "base_url=$BASE_URL"

alive() { curl -fsS -o /dev/null --max-time 3 "$BASE_URL/ping" 2>/dev/null; }

if alive; then
    info "service already running"
else
    if [[ -n "${WEB_START_CMD:-}" ]]; then
        info "starting via WEB_START_CMD"
        ( cd "$PROJECT_DIR" && eval "$WEB_START_CMD" ) >/tmp/tdx_gpu_web_start.log 2>&1 &
        SERVER_PID=$!
    else
        info "starting via 'cargo run' on port $BASE_PORT"
        ( cd "$PROJECT_DIR" && ROCKET_PORT="$BASE_PORT" ROCKET_ADDRESS=127.0.0.1 \
            cargo run >/tmp/tdx_gpu_web_start.log 2>&1 ) &
        SERVER_PID=$!
    fi

    for _ in $(seq 1 60); do
        alive && break
        sleep 1
    done

    if alive; then
        ok "service came up"
    else
        bad "service did not come up within 60s"
        info "last log lines:"
        tail -n 30 /tmp/tdx_gpu_web_start.log 2>/dev/null | sed 's/^/       /'
        echo
        echo "gpu web test: FAILED (could not start service)"
        exit 1
    fi
fi

echo

# ---------------------------------------------------------------------------
# 1. GET /gpu-attestation
# ---------------------------------------------------------------------------

echo "== 1. GET /gpu-attestation =="

status=$(curl -sS -o /tmp/gpu_attestation.json -w '%{http_code}' --max-time 60 \
    "$BASE_URL/gpu-attestation")

if [[ "$status" == "200" ]]; then
    ok "GET /gpu-attestation -> 200"
else
    bad "GET /gpu-attestation -> $status (expected 200)"
    info "body: $(head -c 300 /tmp/gpu_attestation.json 2>/dev/null)"
fi

# The body must be a JSON object carrying a non-empty `gpu-attestation` string.
if python3 -c '
import json, sys
with open("/tmp/gpu_attestation.json") as fh:
    payload = json.load(fh)
value = payload.get("gpu-attestation")
assert isinstance(value, str) and value.strip(), "missing or empty gpu-attestation"
' 2>/dev/null; then
    ok "body carries a non-empty 'gpu-attestation' string"
else
    bad "body does not carry a non-empty 'gpu-attestation' string"
    info "body: $(head -c 300 /tmp/gpu_attestation.json 2>/dev/null)"
fi

echo
echo "gpu web test: PASS=$PASS FAIL=$FAIL"

if [[ "$FAIL" -ne 0 ]]; then
    exit 1
fi
exit 0
