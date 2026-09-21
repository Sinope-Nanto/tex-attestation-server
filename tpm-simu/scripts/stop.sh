#!/usr/bin/env bash
#
# stop.sh - Stop the TPM 2.0 Reference Simulator
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PID_FILE="${ROOT_DIR}/tpm-simulator.pid"

if [[ ! -f "${PID_FILE}" ]]; then
    echo "TPM simulator is not running (no PID file)."
    exit 0
fi

PID="$(cat "${PID_FILE}" 2>/dev/null || true)"

if [[ -z "${PID}" ]]; then
    echo "PID file is empty; removing it."
    rm -f "${PID_FILE}"
    exit 0
fi

if ! kill -0 "${PID}" 2>/dev/null; then
    echo "TPM simulator is not running (stale PID ${PID}); removing PID file."
    rm -f "${PID_FILE}"
    exit 0
fi

echo "Stopping TPM simulator (PID ${PID})..."
kill "${PID}" 2>/dev/null || true

# Wait up to 10 seconds for graceful exit
for _ in $(seq 1 50); do
    if ! kill -0 "${PID}" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

if kill -0 "${PID}" 2>/dev/null; then
    echo "Process did not exit gracefully; sending SIGKILL."
    kill -9 "${PID}" 2>/dev/null || true
    sleep 0.5
fi

rm -f "${PID_FILE}"
echo "TPM simulator stopped."
