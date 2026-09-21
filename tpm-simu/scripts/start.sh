#!/usr/bin/env bash
#
# start.sh - Start the Microsoft / TCG TPM 2.0 Reference Simulator
#
# This script launches the tpm2-simulator binary in the background,
# records its PID, and stores all runtime state (NVChip, port files)
# inside the deployment directory.
#
set -euo pipefail

# Resolve deployment root (parent of this script's directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

BIN="${ROOT_DIR}/bin/tpm2-simulator"
STATE_DIR="${ROOT_DIR}/state"
LOG_DIR="${ROOT_DIR}/logs"
PID_FILE="${ROOT_DIR}/tpm-simulator.pid"
LOG_FILE="${LOG_DIR}/tpm-simulator.log"

# Default TCP port for the TPM command interface.
# The platform interface listens on PORT+1 (see TcpServer.c).
PORT="${TPM_SIM_PORT:-2321}"

# Optional extra arguments (e.g. "-m" to force re-manufacture)
EXTRA_ARGS="${TPM_SIM_ARGS:-}"

mkdir -p "${STATE_DIR}" "${LOG_DIR}"

if [[ ! -x "${BIN}" ]]; then
    echo "ERROR: simulator binary not found or not executable: ${BIN}" >&2
    exit 1
fi

# --- Check for an already running instance ---------------------------------
if [[ -f "${PID_FILE}" ]]; then
    OLD_PID="$(cat "${PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${OLD_PID}" ]] && kill -0 "${OLD_PID}" 2>/dev/null; then
        echo "TPM simulator is already running (PID ${OLD_PID})."
        echo "Use scripts/stop.sh first if you want to restart it."
        exit 0
    else
        # Stale PID file
        rm -f "${PID_FILE}"
    fi
fi

# --- Check whether the port is already in use -------------------------------
if command -v ss >/dev/null 2>&1; then
    if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}$"; then
        echo "ERROR: TCP port ${PORT} is already in use." >&2
        echo "Set TPM_SIM_PORT to a free port, or stop the process using it." >&2
        exit 1
    fi
fi

# --- Launch the simulator ---------------------------------------------------
# The simulator writes NVChip / command.port / platform.port into its CWD,
# so we run it from the state directory to keep everything self-contained.
cd "${STATE_DIR}"

# shellcheck disable=SC2086
nohup "${BIN}" ${PORT} ${EXTRA_ARGS} >>"${LOG_FILE}" 2>&1 &
NEW_PID=$!
echo "${NEW_PID}" > "${PID_FILE}"

# Give it a moment to bind the sockets
sleep 1

if ! kill -0 "${NEW_PID}" 2>/dev/null; then
    echo "ERROR: simulator failed to start. See ${LOG_FILE}" >&2
    rm -f "${PID_FILE}"
    exit 1
fi

# Verify the command port is actually listening
if command -v ss >/dev/null 2>&1; then
    if ! ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${PORT}$"; then
        echo "ERROR: simulator process is alive but not listening on port ${PORT}." >&2
        echo "See ${LOG_FILE} for details." >&2
        exit 1
    fi
fi

echo "TPM simulator started."
echo "  PID:            ${NEW_PID}"
echo "  Command port:   ${PORT}"
echo "  Platform port:  $((PORT + 1))"
echo "  State dir:      ${STATE_DIR}"
echo "  Log file:       ${LOG_FILE}"
