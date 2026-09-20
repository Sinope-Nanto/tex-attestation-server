#!/usr/bin/env bash
#
# End-to-end HTTP test of the TDX attestation service, driven purely with
# curl(1).
#
# Endpoints are taken from src/api.rs:
#
#   GET  /ping                                   -> 200 "pong"
#   GET  /attestation-with-randomnumber?rn=<hex> -> 200 {"report":"<hex>"}
#   POST /verify-report  {"report":"<hex>"}     -> 200 {"trusted":bool}
#
# Environment:
#   WEB_BASE_URL   base URL of a *running* service (default http://127.0.0.1:8080)
#   WEB_START_CMD  command that starts the service; when unset and the service
#                  is not already answering, `cargo run` is used with
#                  ROCKET_PORT derived from WEB_BASE_URL.
#
# The script exits 0 only if every check passes.

set -uo pipefail

BASE_URL="${WEB_BASE_URL:-http://127.0.0.1:8080}"
BASE_URL="${BASE_URL%/}"

# Port the service must listen on, derived from the base URL.
BASE_PORT="$(printf '%s' "$BASE_URL" | sed -n 's#.*:\([0-9]\{1,5\}\)$#\1#p')"
BASE_PORT="${BASE_PORT:-8080}"

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
        ( cd "$PROJECT_DIR" && eval "$WEB_START_CMD" ) >/tmp/tdx_web_start.log 2>&1 &
        SERVER_PID=$!
    else
        info "starting via 'cargo run' on port $BASE_PORT"
        ( cd "$PROJECT_DIR" && ROCKET_PORT="$BASE_PORT" ROCKET_ADDRESS=127.0.0.1 \
            cargo run >/tmp/tdx_web_start.log 2>&1 ) &
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
        tail -n 30 /tmp/tdx_web_start.log 2>/dev/null | sed 's/^/       /'
        echo
        echo "web test: FAILED (could not start service)"
        exit 1
    fi
fi

echo

# ---------------------------------------------------------------------------
# 1. health / root API
# ---------------------------------------------------------------------------

echo "== 1. health / liveness =="

status=$(curl -sS -o /tmp/w_ping.txt -w '%{http_code}' --max-time 10 "$BASE_URL/ping")
body=$(cat /tmp/w_ping.txt)
if [[ "$status" == "200" && "$body" == "pong" ]]; then
    ok "GET /ping -> 200 pong"
else
    bad "GET /ping -> $status '$body' (expected 200 pong)"
fi

# Unknown route must be a JSON 404, not an HTML error page.
status=$(curl -sS -o /tmp/w_404.txt -w '%{http_code}' --max-time 10 "$BASE_URL/no-such-route")
if [[ "$status" == "404" ]] && grep -q '"error"' /tmp/w_404.txt; then
    ok "GET /no-such-route -> 404 with JSON error envelope"
else
    bad "GET /no-such-route -> $status $(cat /tmp/w_404.txt) (expected 404 JSON)"
fi

echo

# ---------------------------------------------------------------------------
# 2. get report API
# ---------------------------------------------------------------------------

echo "== 2. get report API =="

RN=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
status=$(curl -sS -o /tmp/w_report.json -w '%{http_code}' --max-time 30 \
    "$BASE_URL/attestation-with-randomnumber?rn=$RN")

REPORT_HEX=""
if [[ "$status" == "200" ]]; then
    REPORT_HEX=$(jq -r '.report // empty' /tmp/w_report.json 2>/dev/null)
fi

if [[ "$status" == "200" && -n "$REPORT_HEX" ]]; then
    ok "GET /attestation-with-randomnumber -> 200, report returned"
else
    bad "GET /attestation-with-randomnumber -> $status $(cat /tmp/w_report.json)"
    info "is /dev/tdx_guest present? report generation needs real TDX hardware"
fi

# The report must be exactly 1024 bytes, i.e. 2048 hex characters.
if [[ -n "$REPORT_HEX" ]]; then
    if [[ "${#REPORT_HEX}" == "2048" ]]; then
        ok "report is 1024 bytes (2048 hex chars)"
    else
        bad "report is ${#REPORT_HEX} hex chars (expected 2048)"
    fi

    # REPORTDATA must be echoed at offset 0x80 (bytes 128..192 -> hex 256..384).
    embedded="${REPORT_HEX:256:128}"
    if [[ "$embedded" == "$RN" ]]; then
        ok "report[0x80..0xc0] == the supplied 64-byte rn (REPORTDATA bound)"
    else
        bad "REPORTDATA not echoed: got $embedded want $RN"
    fi
fi

# Malformed rn must be a 4xx, not a 500.
status=$(curl -sS -o /tmp/w_badrn.json -w '%{http_code}' --max-time 10 \
    "$BASE_URL/attestation-with-randomnumber?rn=zzzz")
if [[ "$status" == "400" ]]; then
    ok "non-hex rn -> 400"
else
    bad "non-hex rn -> $status (expected 400)"
fi

# Missing rn must be a 4xx.
status=$(curl -sS -o /tmp/w_norn.json -w '%{http_code}' --max-time 10 \
    "$BASE_URL/attestation-with-randomnumber")
if [[ "$status" == "400" ]]; then
    ok "missing rn -> 400"
else
    bad "missing rn -> $status (expected 400)"
fi

echo

# ---------------------------------------------------------------------------
# 3. verify report API - pristine report must be trusted
# ---------------------------------------------------------------------------

echo "== 3. verify report API =="

if [[ -z "$REPORT_HEX" ]]; then
    bad "cannot test verification without a report from step 2"
else
    status=$(curl -sS -o /tmp/w_verify.json -w '%{http_code}' --max-time 30 \
        -X POST -H 'Content-Type: application/json' \
        -d "{\"report\":\"$REPORT_HEX\"}" \
        "$BASE_URL/verify-report")

    if [[ "$status" == "200" ]]; then
        trusted=$(jq -r '.trusted' /tmp/w_verify.json 2>/dev/null)
        if [[ "$trusted" == "true" ]]; then
            ok "pristine report -> 200 {\"trusted\":true}"
            echo "backend=TDG.MR.VERIFYREPORT"
            echo "fresh report verification: PASS"
        else
            bad "pristine report -> trusted=$trusted (expected true)"
        fi
    else
        bad "pristine report -> $status $(cat /tmp/w_verify.json)"
        info "is /dev/tdx_verify present? load the helper module"
    fi
fi

# ---------------------------------------------------------------------------
# 4. tampered report must be rejected
# ---------------------------------------------------------------------------

echo

if [[ -z "$REPORT_HEX" ]]; then
    bad "cannot test tampering without a report from step 2"
else
    # Flip one bit inside REPORTMACSTRUCT.REPORTDATA (byte offset 0x80).
    # Hex offset 256; two hex chars encode that one byte.
    prefix="${REPORT_HEX:0:256}"
    byte="${REPORT_HEX:256:2}"
    rest="${REPORT_HEX:258}"
    flipped=$(printf '%02x' $(( 0x$byte ^ 0x01 )))
    TAMPERED_HEX="${prefix}${flipped}${rest}"

    if [[ "$TAMPERED_HEX" == "$REPORT_HEX" ]]; then
        bad "failed to construct a tampered report"
    else
        status=$(curl -sS -o /tmp/w_tampered.json -w '%{http_code}' --max-time 30 \
            -X POST -H 'Content-Type: application/json' \
            -d "{\"report\":\"$TAMPERED_HEX\"}" \
            "$BASE_URL/verify-report")

        if [[ "$status" == "200" ]]; then
            trusted=$(jq -r '.trusted' /tmp/w_tampered.json 2>/dev/null)
            if [[ "$trusted" == "false" ]]; then
                ok "tampered REPORTDATA -> 200 {\"trusted\":false}"
                echo "tampered report verification: FAIL (as required)"
            else
                bad "tampered report -> trusted=$trusted (expected false!)"
            fi
        else
            bad "tampered report -> $status $(cat /tmp/w_tampered.json)"
        fi
    fi
fi

echo

# ---------------------------------------------------------------------------
# 4b. parse report API - decode a report into human readable JSON
# ---------------------------------------------------------------------------

echo "== 4b. parse report API =="

if [[ -z "$REPORT_HEX" ]]; then
    bad "cannot test parsing without a report from step 2"
else
    status=$(curl -sS -o /tmp/w_parse.json -w '%{http_code}' --max-time 30 \
        -X POST -H 'Content-Type: application/json' \
        -d "{\"report\":\"$REPORT_HEX\"}" \
        "$BASE_URL/parse-report")

    if [[ "$status" == "200" ]]; then
        ok "POST /parse-report -> 200"

        # The decoded REPORTDATA must equal the nonce we bound the report to.
        parsed_rd=$(jq -r '.report_mac_struct.report_data' /tmp/w_parse.json 2>/dev/null)
        if [[ "$parsed_rd" == "$RN" ]]; then
            ok "parsed report_mac_struct.report_data == the supplied rn"
        else
            bad "parsed report_data=$parsed_rd want $RN"
        fi

        # The MAC must be 32 bytes (64 hex chars).
        mac=$(jq -r '.report_mac_struct.mac' /tmp/w_parse.json 2>/dev/null)
        if [[ "${#mac}" == "64" ]]; then
            ok "parsed report_mac_struct.mac is 32 bytes"
        else
            bad "parsed mac is ${#mac} hex chars (expected 64)"
        fi

        # MRTD must be 48 bytes (96 hex chars).
        mrtd=$(jq -r '.tdinfo.mrtd' /tmp/w_parse.json 2>/dev/null)
        if [[ "${#mrtd}" == "96" ]]; then
            ok "parsed tdinfo.mrtd is 48 bytes"
        else
            bad "parsed mrtd is ${#mrtd} hex chars (expected 96)"
        fi

        # report_len must be 1024.
        rlen=$(jq -r '.report_len' /tmp/w_parse.json 2>/dev/null)
        if [[ "$rlen" == "1024" ]]; then
            ok "parsed report_len == 1024"
        else
            bad "parsed report_len=$rlen (expected 1024)"
        fi
    else
        bad "POST /parse-report -> $status $(cat /tmp/w_parse.json)"
    fi
fi

# Non-hex report must be a 400.
status=$(curl -sS -o /tmp/w_parse_bad.json -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' \
    -d '{"report":"nothex"}' "$BASE_URL/parse-report")
if [[ "$status" == "400" ]]; then
    ok "parse-report non-hex report -> 400"
else
    bad "parse-report non-hex report -> $status (expected 400)"
fi

# Wrong length report must be a 400.
status=$(curl -sS -o /tmp/w_parse_short.json -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' \
    -d '{"report":"aabbccdd"}' "$BASE_URL/parse-report")
if [[ "$status" == "400" ]]; then
    ok "parse-report short report -> 400"
else
    bad "parse-report short report -> $status (expected 400)"
fi

echo

# ---------------------------------------------------------------------------
# 5. invalid requests must be 4xx (never 5xx, never a crash)
# ---------------------------------------------------------------------------

echo "== 4. invalid requests =="

status=$(curl -sS -o /tmp/w_nh.json -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' \
    -d '{"report":"nothex"}' "$BASE_URL/verify-report")
if [[ "$status" == "400" ]]; then
    ok "non-hex report -> 400"
else
    bad "non-hex report -> $status (expected 400)"
fi

status=$(curl -sS -o /tmp/w_bj.json -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' \
    -d 'this-is-not-json' "$BASE_URL/verify-report")
if [[ "$status" == "400" ]]; then
    ok "malformed JSON body -> 400"
else
    bad "malformed JSON body -> $status (expected 400)"
fi

# Well-formed hex but the wrong length: a client error, not a server error.
status=$(curl -sS -o /tmp/w_sr.json -w '%{http_code}' --max-time 10 \
    -X POST -H 'Content-Type: application/json' \
    -d '{"report":"aabbccdd"}' "$BASE_URL/verify-report")
if [[ "$status" == "400" ]]; then
    ok "short (non-1024-byte) report -> 400"
else
    bad "short report -> $status (expected 400)"
fi

# Every error response must carry the JSON envelope.
for f in /tmp/w_badrn.json /tmp/w_norn.json /tmp/w_nh.json /tmp/w_bj.json /tmp/w_sr.json; do
    if ! grep -q '"error"' "$f" 2>/dev/null; then
        bad "error response $f is missing the {\"error\":...} envelope"
    fi
done
ok "all error responses use the {\"error\":...} envelope"

echo
if [[ "$FAIL" -eq 0 ]]; then
    printf 'web test: PASSED (%d checks)\n' "$PASS"
    exit 0
fi

printf 'web test: FAILED (%d passed, %d failed)\n' "$PASS" "$FAIL"
exit 1
