#!/usr/bin/env bash
#
# test.sh - End-to-end smoke test for the deployed TPM 2.0 simulator
#
# Tests:
#   1. binary exists and is executable
#   2. start.sh brings the simulator up
#   3. the TCP command port is actually listening
#   4. a real TPM command round-trip (via tpm2-tools if available,
#      otherwise a raw TPM2_GetCapability over the simulator protocol)
#   5. stop + start (restart) works
#   6. final state is RUNNING
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

BIN="${ROOT_DIR}/bin/tpm2-simulator"
START="${SCRIPT_DIR}/start.sh"
STOP="${SCRIPT_DIR}/stop.sh"
STATUS="${SCRIPT_DIR}/status.sh"

PORT="${TPM_SIM_PORT:-2321}"

PASS=0
FAIL=0

ok()   { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }

port_listening() {
    local p="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
    else
        # Fallback: try to connect with python
        python3 - "$p" <<'PY'
import socket, sys
p = int(sys.argv[1])
s = socket.socket()
s.settimeout(1.0)
try:
    s.connect(("127.0.0.1", p))
    s.close()
    sys.exit(0)
except Exception:
    sys.exit(1)
PY
    fi
}

echo "=============================================="
echo " TPM 2.0 Simulator deployment test"
echo "=============================================="

# ---------------------------------------------------------------------------
# Test 1: binary
# ---------------------------------------------------------------------------
echo
echo "[Test 1] binary present and executable"
if [[ -x "${BIN}" ]]; then
    ok "${BIN} exists and is executable"
else
    fail "${BIN} missing or not executable"
fi

# ---------------------------------------------------------------------------
# Test 2: start
# ---------------------------------------------------------------------------
echo
echo "[Test 2] start.sh"
# Ensure clean state
"${STOP}" >/dev/null 2>&1 || true
if "${START}" >/tmp/tpm-simu-start.log 2>&1; then
    ok "start.sh returned success"
else
    fail "start.sh failed; log:"
    cat /tmp/tpm-simu-start.log
fi

PID_FILE="${ROOT_DIR}/tpm-simulator.pid"
if [[ -f "${PID_FILE}" ]] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
    ok "simulator process is alive (PID $(cat "${PID_FILE}"))"
else
    fail "simulator process is not running"
fi

# ---------------------------------------------------------------------------
# Test 3: port
# ---------------------------------------------------------------------------
echo
echo "[Test 3] TCP command port ${PORT} listening"
if port_listening "${PORT}"; then
    ok "port ${PORT} is listening"
else
    fail "port ${PORT} is NOT listening"
fi

# ---------------------------------------------------------------------------
# Test 4: real TPM communication
# ---------------------------------------------------------------------------
echo
echo "[Test 4] TPM command round-trip"
if command -v tpm2_getrandom >/dev/null 2>&1; then
    export TPM2TOOLS_TCTI="mssim:host=127.0.0.1,port=${PORT}"
    # Startup is required after power-on; ignore error if already started
    tpm2_startup -c >/dev/null 2>&1 || true
    RAND="$(tpm2_getrandom 8 2>/dev/null | xxd -p 2>/dev/null || true)"
    if [[ -n "${RAND}" && ${#RAND} -ge 16 ]]; then
        ok "tpm2_getrandom returned ${RAND}"
    else
        fail "tpm2_getrandom did not return random bytes"
    fi
    CAP="$(tpm2_getcap properties-fixed 2>/dev/null | head -3 || true)"
    if echo "${CAP}" | grep -q "TPM2_PT_FAMILY_INDICATOR"; then
        ok "tpm2_getcap properties-fixed returned TPM properties"
    else
        fail "tpm2_getcap did not return expected properties"
    fi
else
    echo "  [INFO] tpm2-tools not installed; falling back to raw protocol test"
    python3 - "${PORT}" <<'PY'
import socket, struct, sys
port = int(sys.argv[1])
s = socket.socket()
s.settimeout(3.0)
s.connect(("127.0.0.1", port))

# --- Platform interface (port+1) is separate; here we use the command port.
# Send TPM2_GetCapability (TPM_CC_GetCapability = 0x0000017A)
#   capability = TPM_CAP_TPM_PROPERTIES (0x00000006)
#   property   = TPM_PT_FAMILY_INDICATOR (0x00000100)
#   propertyCount = 1
cmd = struct.pack(">HII", 0x8001, 0x0000017A, 0x00000006) + struct.pack(">II", 0x00000100, 1)
# TPM_SEND_COMMAND = 8, locality = 0, then uint32 length + payload
msg = struct.pack(">I", 8) + struct.pack(">B", 0) + struct.pack(">I", len(cmd)) + cmd
s.sendall(msg)

# Response: uint32 outSize, then outSize bytes, then uint32 ack
hdr = s.recv(4)
if len(hdr) < 4:
    print("no response header")
    sys.exit(1)
out_size = struct.unpack(">I", hdr)[0]
body = b""
while len(body) < out_size:
    chunk = s.recv(out_size - len(body))
    if not chunk:
        break
    body += chunk
ack = s.recv(4)
s.close()

if out_size < 10:
    print("response too short:", body.hex())
    sys.exit(1)
# TPM response header: tag(2) size(4) rc(4)
tag, size, rc = struct.unpack(">HII", body[:10])
if rc != 0:
    print("TPM returned rc=0x%08x" % rc)
    sys.exit(1)
print("TPM2_GetCapability OK: tag=0x%04x size=%d rc=0x%08x" % (tag, size, rc))
sys.exit(0)
PY
    if [[ $? -eq 0 ]]; then
        ok "raw TPM2_GetCapability round-trip succeeded"
    else
        fail "raw TPM2_GetCapability round-trip failed"
    fi
fi

# ---------------------------------------------------------------------------
# Test 5: restart
# ---------------------------------------------------------------------------
echo
echo "[Test 5] restart (stop + start + status)"
"${STOP}" >/dev/null 2>&1 || true
if port_listening "${PORT}"; then
    fail "port ${PORT} still listening after stop"
else
    ok "port ${PORT} released after stop"
fi

if "${START}" >/tmp/tpm-simu-restart.log 2>&1; then
    ok "start.sh succeeded on restart"
else
    fail "start.sh failed on restart"
    cat /tmp/tpm-simu-restart.log
fi

if port_listening "${PORT}"; then
    ok "port ${PORT} listening after restart"
else
    fail "port ${PORT} NOT listening after restart"
fi

STATUS_OUT="$("${STATUS}" 2>&1 || true)"
if echo "${STATUS_OUT}" | grep -q "^RUNNING"; then
    ok "status.sh reports RUNNING"
else
    fail "status.sh did not report RUNNING: ${STATUS_OUT}"
fi

# ---------------------------------------------------------------------------
# Test 6: final state
# ---------------------------------------------------------------------------
echo
echo "[Test 6] final state"
if port_listening "${PORT}"; then
    ok "simulator is RUNNING on port ${PORT}"
else
    fail "simulator is not running at end of test"
fi

echo
echo "=============================================="
echo " Results: ${PASS} passed, ${FAIL} failed"
echo "=============================================="

if [[ ${FAIL} -gt 0 ]]; then
    exit 1
fi
exit 0
