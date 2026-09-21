#!/usr/bin/env bash
#
# status.sh - Report the status of the TPM 2.0 Reference Simulator
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

PID_FILE="${ROOT_DIR}/tpm-simulator.pid"
STATE_DIR="${ROOT_DIR}/state"
PORT="${TPM_SIM_PORT:-2321}"

if [[ ! -f "${PID_FILE}" ]]; then
    echo "STOPPED"
    exit 0
fi

PID="$(cat "${PID_FILE}" 2>/dev/null || true)"

if [[ -z "${PID}" ]] || ! kill -0 "${PID}" 2>/dev/null; then
    echo "STOPPED"
    exit 0
fi

echo "RUNNING"
echo "  PID:            ${PID}"

# Report the actual listening ports if we can determine them
if command -v ss >/dev/null 2>&1; then
    PORTS="$(ss -tlnp 2>/dev/null | grep "pid=${PID}," | awk '{print $4}' | awk -F: '{print $NF}' | sort -u | tr '\n' ' ' || true)"
    if [[ -n "${PORTS// /}" ]]; then
        echo "  Listening ports: ${PORTS}"
    else
        echo "  Listening ports: (none detected)"
    fi
fi

# Report the port files written by the simulator, if present
if [[ -f "${STATE_DIR}/command.port" ]]; then
    echo "  Command port (from state):  $(cat "${STATE_DIR}/command.port")"
fi
if [[ -f "${STATE_DIR}/platform.port" ]]; then
    echo "  Platform port (from state): $(cat "${STATE_DIR}/platform.port")"
fi

echo "  Configured base port:       ${PORT}"
