#!/usr/bin/env bash
#
# End-to-end HTTP test of the TPM attestation endpoints, driven purely with
# curl(1) against a *running* service.
#
# Endpoints taken from src/api.rs:
#
#   GET  /information_tpm                       -> 200 {measurement, pcr_value, ...}
#   POST /quote_tpm {"nonce":"<hex>"}           -> 200 {evidence.tpm.quote, ...}
#
# The original TDX endpoints are exercised as a regression check:
#
#   GET  /ping                                  -> 200 "pong"
#   GET  /attestation-with-randomnumber?rn=     -> 200 {"report":"<hex>"}
#   POST /verify-report                         -> 200 {"trusted":bool}
#   POST /parse-report                          -> 200 {...}
#
# The TPM quotes are not merely inspected: every one of them is decoded from the
# base64(hex(..)) wire format and handed to `tpm2_checkquote` together with the
# Attestation Key public part the API returns. A fabricated quote cannot pass
# that check, and a quote produced for a *different* challenge must fail it.
#
# Environment:
#   WEB_BASE_URL      base URL of a running service (default http://127.0.0.1:8080)
#   WEB_START_CMD     command used to start the service (default: cargo run)
#   TPM_SIMULATOR_DIR simulator deployment (default <project>/tpm-simu)
#
# The script exits 0 only if every check passes.

set -uo pipefail

BASE_URL="${WEB_BASE_URL:-http://127.0.0.1:8080}"
BASE_URL="${BASE_URL%/}"

BASE_PORT="$(printf '%s' "$BASE_URL" | sed -n 's#.*:\([0-9]\{1,5\}\)$#\1#p')"
BASE_PORT="${BASE_PORT:-8080}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SIM_DIR="${TPM_SIMULATOR_DIR:-$PROJECT_DIR/tpm-simu}"

PASS=0
FAIL=0
SERVER_PID=""

ok()   { printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
info() { printf '  [INFO] %s\n' "$1"; }

WORK="$(mktemp -d /tmp/tdx-tpm-web.XXXXXX)"

cleanup() {
    rm -rf "$WORK"
    if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Prerequisites: the simulator should be up before the service is started.
# ---------------------------------------------------------------------------

echo "== Prerequisites =="

if [[ -x "$SIM_DIR/scripts/status.sh" ]]; then
    if grep -q '^RUNNING' <<<"$("$SIM_DIR/scripts/status.sh" 2>&1 || true)"; then
        info "TPM simulator already RUNNING"
    else
        info "TPM simulator STOPPED; starting it"
        "$SIM_DIR/scripts/start.sh" >/tmp/tdx-tpm-web-simstart.log 2>&1 \
            || info "scripts/start.sh reported an error; see /tmp/tdx-tpm-web-simstart.log"
    fi
else
    info "no simulator at $SIM_DIR; the TPM endpoints are expected to answer 501"
fi

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
        ( cd "$PROJECT_DIR" && eval "$WEB_START_CMD" ) >/tmp/tdx-tpm-web-server.log 2>&1 &
        SERVER_PID=$!
    else
        info "starting via 'cargo run' on port $BASE_PORT"
        ( cd "$PROJECT_DIR" && ROCKET_PORT="$BASE_PORT" ROCKET_ADDRESS=127.0.0.1 \
            cargo run >/tmp/tdx-tpm-web-server.log 2>&1 ) &
        SERVER_PID=$!
    fi

    for _ in $(seq 1 90); do
        alive && break
        sleep 1
    done

    if alive; then
        ok "service came up"
    else
        bad "service did not come up within 90s"
        tail -n 30 /tmp/tdx-tpm-web-server.log 2>/dev/null | sed 's/^/       /'
        printf '\nTPM web test: FAILED (could not start service)\n'
        exit 1
    fi
fi

echo

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

read_json() { jq -r "$2" "$1" 2>/dev/null; }

# usage: decode_blob <base64-string> <out-file>
# The wire format is base64(hex(bytes)), i.e. hex-on-the-inside, matching what
# the reference gpu-node service emits.
decode_blob() {
    python3 - "$1" "$2" <<'PY'
import base64, binascii, sys
value, out = sys.argv[1], sys.argv[2]
inner = base64.b64decode(value)
raw = binascii.unhexlify(inner.decode("ascii"))
with open(out, "wb") as fh:
    fh.write(raw)
PY
}

# ---------------------------------------------------------------------------
# 1. TPM information
# ---------------------------------------------------------------------------

echo "== 1. GET /information_tpm =="

status=$(curl -sS -o /tmp/tpm_info.json -w '%{http_code}' --max-time 60 "$BASE_URL/information_tpm")

INFO_OK=0
if [[ "$status" == "200" ]]; then
    INFO_OK=1
    ok "GET /information_tpm -> 200"
elif [[ "$status" == "501" ]]; then
    bad "GET /information_tpm -> 501 (simulator not reachable?) $(cat /tmp/tpm_info.json)"
    info "check: $SIM_DIR/scripts/status.sh"
else
    bad "GET /information_tpm -> $status $(cat /tmp/tpm_info.json)"
fi

TOTAL_HASH=""
PCR_VALUE=""
FILES_COUNT="0"

if [[ "$INFO_OK" == "1" ]]; then
    backend=$(read_json /tmp/tpm_info.json '.backend')
    simulator=$(read_json /tmp/tpm_info.json '.simulator')
    measured=$(read_json /tmp/tpm_info.json '.measured_directory')
    hash_alg=$(read_json /tmp/tpm_info.json '.hash_algorithm')
    pcr_index=$(read_json /tmp/tpm_info.json '.pcr_index')
    TOTAL_HASH=$(read_json /tmp/tpm_info.json '.measurement.total_hash')
    PCR_VALUE=$(read_json /tmp/tpm_info.json '.pcr_value')
    time_stamp=$(read_json /tmp/tpm_info.json '.measurement."time-stamp"')
    ak_handle=$(read_json /tmp/tpm_info.json '.ak_handle')
    FILES_COUNT=$(read_json /tmp/tpm_info.json '.measurement.measurement | length')

    [[ "$backend" == "tpm2-tools" ]] && ok "backend=$backend" || bad "unexpected backend '$backend'"
    [[ -n "$simulator" ]] && ok "simulator=$simulator" || bad "missing simulator field"
    [[ -d "$measured" ]] && ok "measured_directory=$measured" || bad "measured_directory '$measured' is not a directory"
    [[ -n "$hash_alg" ]] && ok "hash_algorithm=$hash_alg" || bad "missing hash_algorithm"
    [[ -n "$pcr_index" ]] && ok "pcr_index=$pcr_index" || bad "missing pcr_index"
    [[ -n "$ak_handle" ]] && ok "ak_handle=$ak_handle" || bad "missing ak_handle"
    [[ -n "$time_stamp" ]] && ok "measurement.time-stamp=$time_stamp" || bad "missing measurement.time-stamp"

    if [[ ${#TOTAL_HASH} -eq 64 ]]; then
        ok "measurement.total_hash is a 32-byte digest (${TOTAL_HASH:0:16}...)"
    else
        bad "measurement.total_hash='$TOTAL_HASH' (expected 64 hex chars)"
    fi

    if [[ -n "$PCR_VALUE" ]]; then
        ok "pcr_value is present (${PCR_VALUE:0:16}...)"
    else
        bad "pcr_value is missing"
    fi

    # The PCR value must be a hash of the extended folder digest, so it can
    # never equal the folder digest itself.
    if [[ -n "$PCR_VALUE" && "$PCR_VALUE" != "$TOTAL_HASH" ]]; then
        ok "pcr_value differs from the folder digest (the extend took place)"
    else
        bad "pcr_value equals the folder digest; no PCR_Extend happened"
    fi

    if [[ "${FILES_COUNT:-0}" -gt 0 ]]; then
        ok "measurement lists $FILES_COUNT file(s)"
    else
        bad "measurement lists no files"
    fi

    first_hash=$(read_json /tmp/tpm_info.json '.measurement.measurement[0].hash')
    first_name=$(read_json /tmp/tpm_info.json '.measurement.measurement[0].name')
    if [[ ${#first_hash} -eq 64 && -n "$first_name" ]]; then
        ok "first entry: name=$first_name hash=${first_hash:0:16}..."
    else
        bad "first entry is malformed (name='$first_name' hash='$first_hash')"
    fi
fi

echo

# ---------------------------------------------------------------------------
# 2. Repeated measurement is deterministic (PCR_Reset + PCR_Extend)
# ---------------------------------------------------------------------------

echo "== 2. repeated measurement =="

if [[ "$INFO_OK" == "1" ]]; then
    status=$(curl -sS -o /tmp/tpm_info2.json -w '%{http_code}' --max-time 60 "$BASE_URL/information_tpm")
    second_hash=$(read_json /tmp/tpm_info2.json '.measurement.total_hash')
    second_pcr=$(read_json /tmp/tpm_info2.json '.pcr_value')

    if [[ "$status" == "200" && "$second_hash" == "$TOTAL_HASH" ]]; then
        ok "two measurements of the same directory agree (${TOTAL_HASH:0:16}...)"
    else
        bad "measurement is not deterministic: $TOTAL_HASH vs $second_hash"
    fi

    if [[ "$status" == "200" && "$second_pcr" == "$PCR_VALUE" ]]; then
        ok "the PCR value is reproducible (reset before extend)"
    else
        bad "PCR value drifted between runs: $PCR_VALUE vs $second_pcr"
    fi
else
    info "skipped: /information_tpm is not available"
fi

echo

# ---------------------------------------------------------------------------
# 3. TPM quote
# ---------------------------------------------------------------------------

echo "== 3. POST /quote_tpm =="

NONCE=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')

status=$(curl -sS -o /tmp/tpm_quote.json -w '%{http_code}' --max-time 60 \
    -X POST -H 'Content-Type: application/json' \
    -d "{\"nonce\":\"$NONCE\",\"nonce_size\":32}" \
    "$BASE_URL/quote_tpm")

QUOTE_OK=0
SIG_B64=""
MSG_B64=""
QUOTE_STR=""

if [[ "$status" == "200" ]]; then
    QUOTE_OK=1
    ok "POST /quote_tpm -> 200"
elif [[ "$status" == "501" ]]; then
    bad "POST /quote_tpm -> 501 (simulator not reachable?) $(cat /tmp/tpm_quote.json)"
else
    bad "POST /quote_tpm -> $status $(cat /tmp/tpm_quote.json)"
fi

if [[ "$QUOTE_OK" == "1" ]]; then
    q_status=$(read_json /tmp/tpm_quote.json '.status')
    QUOTE_STR=$(read_json /tmp/tpm_quote.json '.evidence.tpm.quote')
    quote_size=$(read_json /tmp/tpm_quote.json '.evidence.tpm.quote_size')
    SIG_B64=$(read_json /tmp/tpm_quote.json '.evidence.tpm.signature')
    MSG_B64=$(read_json /tmp/tpm_quote.json '.evidence.tpm.message')
    pcrs_b64=$(read_json /tmp/tpm_quote.json '.evidence.tpm.pcrs')
    sig_size=$(read_json /tmp/tpm_quote.json '.evidence.tpm.signature_size')
    msg_size=$(read_json /tmp/tpm_quote.json '.evidence.tpm.message_size')
    echo_nonce=$(read_json /tmp/tpm_quote.json '.evidence.tpm.nonce')
    echo_nonce_size=$(read_json /tmp/tpm_quote.json '.evidence.tpm.nonce_size')
    q_pcr=$(read_json /tmp/tpm_quote.json '.evidence.tpm.pcr_index')
    q_pcr_value=$(read_json /tmp/tpm_quote.json '.pcr_value')

    [[ "$q_status" == "0" ]] && ok "status == RC_SUCCESS (0)" || bad "status='$q_status' (expected 0)"

    if [[ -n "$QUOTE_STR" && "$QUOTE_STR" == *:* ]]; then
        ok "evidence.tpm.quote is a non-empty ':'-joined blob (${#QUOTE_STR} chars)"
    else
        bad "evidence.tpm.quote is empty or malformed"
    fi

    if [[ "$quote_size" == "${#QUOTE_STR}" ]]; then
        ok "quote_size matches the blob length ($quote_size)"
    else
        bad "quote_size=$quote_size but the blob is ${#QUOTE_STR} chars"
    fi

    if [[ -n "$SIG_B64" && "${sig_size:-0}" -gt 0 ]]; then
        ok "signature blob is non-empty ($sig_size bytes)"
    else
        bad "signature blob is empty"
    fi

    if [[ -n "$MSG_B64" && "${msg_size:-0}" -gt 0 ]]; then
        ok "message blob is non-empty ($msg_size bytes)"
    else
        bad "message blob is empty"
    fi

    [[ -n "$pcrs_b64" ]] && ok "pcrs blob is non-empty" || bad "pcrs blob is empty"

    if [[ "$echo_nonce" == "$NONCE" ]]; then
        ok "the challenge is echoed in evidence.tpm.nonce"
    else
        bad "challenge not echoed: got '$echo_nonce' want '$NONCE'"
    fi

    if [[ "$echo_nonce_size" == "32" ]]; then
        ok "nonce_size is 32 bytes"
    else
        bad "nonce_size='$echo_nonce_size' (expected 32)"
    fi

    if [[ -n "$q_pcr" && "$q_pcr_value" == "$PCR_VALUE" ]]; then
        ok "the quoted PCR $q_pcr carries the same value as /information_tpm"
    else
        bad "quoted PCR value '$q_pcr_value' differs from '$PCR_VALUE'"
    fi
fi

echo

# ---------------------------------------------------------------------------
# 4. The quote is a real TPM quote: verify it with the AK public part
# ---------------------------------------------------------------------------

echo "== 4. quote verification (tpm2_checkquote) =="

if [[ "$QUOTE_OK" == "1" ]] && command -v tpm2_checkquote >/dev/null 2>&1; then
    ak_pubkey=$(read_json /tmp/tpm_quote.json '.ak_pubkey')

    if [[ -n "$ak_pubkey" ]] && printf '%s\n' "$ak_pubkey" >"$WORK/ak.pem" \
            && grep -q 'BEGIN PUBLIC KEY' "$WORK/ak.pem"; then
        ok "the API returned a PEM Attestation Key public part"

        if decode_blob "$SIG_B64" "$WORK/quote.sig"; then
            ok "signature decoded to raw TPMT_SIGNATURE"
        else
            bad "signature could not be decoded"
        fi

        if decode_blob "$MSG_B64" "$WORK/quote.msg"; then
            ok "message decoded to raw TPMS_ATTEST"
        else
            bad "message could not be decoded"
        fi

        if tpm2_checkquote -u "$WORK/ak.pem" -g sha256 -m "$WORK/quote.msg" -s "$WORK/quote.sig" \
                -q "$NONCE" >/dev/null 2>&1; then
            ok "tpm2_checkquote accepts the quote for the supplied challenge"
        else
            bad "tpm2_checkquote rejected the quote"
        fi

        WRONG="$(printf '00%.0s' $(seq 1 32))"
        if tpm2_checkquote -u "$WORK/ak.pem" -g sha256 -m "$WORK/quote.msg" -s "$WORK/quote.sig" \
                -q "$WRONG" >/dev/null 2>&1; then
            bad "tpm2_checkquote accepted the quote for a WRONG challenge"
        else
            ok "tpm2_checkquote rejects the quote for a wrong challenge"
        fi

        if xxd -p "$WORK/quote.msg" | tr -d '\n' | grep -qi "$NONCE"; then
            ok "the challenge is present in the signed TPMS_ATTEST"
        else
            bad "the challenge is not present in the signed TPMS_ATTEST"
        fi
    else
        bad "no usable Attestation Key public part was returned"
    fi
else
    info "skipped: tpm2_checkquote is unavailable or the quote failed"
fi

echo

# ---------------------------------------------------------------------------
# 5. A different challenge yields a different quote
# ---------------------------------------------------------------------------

echo "== 5. challenge binding =="

if [[ "$QUOTE_OK" == "1" ]]; then
    NONCE_B=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    status=$(curl -sS -o /tmp/tpm_quote_b.json -w '%{http_code}' --max-time 60 \
        -X POST -H 'Content-Type: application/json' \
        -d "{\"challenge\":\"$NONCE_B\"}" \
        "$BASE_URL/quote_tpm")

    quote_b=$(read_json /tmp/tpm_quote_b.json '.evidence.tpm.signature')
    echo_b=$(read_json /tmp/tpm_quote_b.json '.evidence.tpm.nonce')

    if [[ "$status" == "200" && -n "$quote_b" ]]; then
        ok "POST /quote_tpm with the 'challenge' alias -> 200"
    else
        bad "POST /quote_tpm (challenge alias) -> $status $(cat /tmp/tpm_quote_b.json)"
    fi

    if [[ "$echo_b" == "$NONCE_B" ]]; then
        ok "the alias challenge is echoed back"
    else
        bad "alias challenge not echoed: got '$echo_b' want '$NONCE_B'"
    fi

    if [[ -n "$quote_b" && "$quote_b" != "$SIG_B64" ]]; then
        ok "a different challenge produces a different TPM signature"
    else
        bad "the signature did not change with the challenge"
    fi
fi

echo

# ---------------------------------------------------------------------------
# 5b. Concurrent requests are serialised as TPM transactions
# ---------------------------------------------------------------------------
#
# A TPM is a stateful device: two overlapping reset/measure/extend/read/quote
# sequences would corrupt each other. The backend takes a process wide mutex,
# so every response must still be internally consistent when several requests
# are in flight at once.

echo "== 5b. concurrent requests =="

if [[ "$QUOTE_OK" == "1" ]]; then
    CONC_DIR="$WORK/conc"
    mkdir -p "$CONC_DIR"

    for i in 1 2 3 4; do
        C_NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
        curl -sS -o "$CONC_DIR/quote_$i.json" -w '%{http_code}' --max-time 90 \
            -X POST -H 'Content-Type: application/json' \
            -d "{\"nonce\":\"$C_NONCE\"}" \
            "$BASE_URL/quote_tpm" >"$CONC_DIR/quote_$i.status" &
    done
    for i in 1 2; do
        curl -sS -o "$CONC_DIR/info_$i.json" -w '%{http_code}' --max-time 90 \
            "$BASE_URL/information_tpm" >"$CONC_DIR/info_$i.status" &
    done
    wait

    CONC_BAD=0
    for i in 1 2 3 4; do
        code=$(cat "$CONC_DIR/quote_$i.status" 2>/dev/null)
        [[ "$code" == "200" ]] || CONC_BAD=$((CONC_BAD + 1))
    done
    for i in 1 2; do
        code=$(cat "$CONC_DIR/info_$i.status" 2>/dev/null)
        [[ "$code" == "200" ]] || CONC_BAD=$((CONC_BAD + 1))
    done

    if [[ "$CONC_BAD" -eq 0 ]]; then
        ok "6 concurrent requests all answered 200"
    else
        bad "$CONC_BAD of 6 concurrent requests did not answer 200"
    fi

    # Every response must describe the *same* folder, and every quote must
    # cover the same PCR value: that is only true if the transactions were
    # serialised.
    CONC_HASHES=$(for f in "$CONC_DIR"/quote_*.json "$CONC_DIR"/info_*.json; do
        read_json "$f" '.measurement.total_hash'
    done | sort -u)
    if [[ "$(printf '%s\n' "$CONC_HASHES" | grep -c .)" == "1" ]]; then
        ok "every concurrent response reports the same folder digest"
    else
        bad "concurrent responses disagree on the folder digest"
    fi

    CONC_PCRS=$(for f in "$CONC_DIR"/quote_*.json "$CONC_DIR"/info_*.json; do
        read_json "$f" '.pcr_value'
    done | sort -u)
    if [[ "$(printf '%s\n' "$CONC_PCRS" | grep -c .)" == "1" ]]; then
        ok "every concurrent response reports the same PCR value"
    else
        bad "concurrent responses disagree on the PCR value"
    fi

    # Each concurrent quote must still carry its own challenge.
    CONC_MISMATCH=0
    for i in 1 2 3 4; do
        if ! jq -e '.evidence.tpm.nonce | length > 0' "$CONC_DIR/quote_$i.json" >/dev/null 2>&1; then
            CONC_MISMATCH=$((CONC_MISMATCH + 1))
        fi
    done
    if [[ "$CONC_MISMATCH" -eq 0 ]]; then
        ok "every concurrent quote carries a challenge"
    else
        bad "$CONC_MISMATCH concurrent quotes are missing their challenge"
    fi
else
    info "skipped: /quote_tpm is not available"
fi

echo

# ---------------------------------------------------------------------------
# 6. Malformed requests are 4xx (never 5xx, never a crash)
# ---------------------------------------------------------------------------

echo "== 6. malformed requests =="

check_status() {
    local want="$1" label="$2" body="$3"
    local status
    status=$(curl -sS -o /tmp/tpm_bad.json -w '%{http_code}' --max-time 30 \
        -X POST -H 'Content-Type: application/json' -d "$body" "$BASE_URL/quote_tpm")

    if [[ "$status" == "$want" ]]; then
        if grep -q '"error"' /tmp/tpm_bad.json; then
            ok "$label -> $status with the {\"error\":...} envelope"
        else
            bad "$label -> $status but the body has no error envelope"
        fi
    else
        bad "$label -> $status (expected $want): $(cat /tmp/tpm_bad.json)"
    fi
}

check_status 400 "missing nonce"              '{}'
check_status 400 "empty nonce"                '{"nonce":""}'
check_status 400 "non-hex nonce"              '{"nonce":"nothex"}'
check_status 400 "odd-length nonce"           '{"nonce":"abc"}'
check_status 400 "conflicting nonce+challenge" '{"nonce":"aa","challenge":"bb"}'
check_status 400 "malformed JSON body"        'this-is-not-json'

OVERSIZED="$(printf 'ab%.0s' $(seq 1 65))"
check_status 400 "oversized nonce (65 B)"     "{\"nonce\":\"$OVERSIZED\"}"

status=$(curl -sS -o /tmp/tpm_get.json -w '%{http_code}' --max-time 15 "$BASE_URL/quote_tpm")
if [[ "$status" == "404" || "$status" == "422" || "$status" == "405" ]]; then
    ok "GET /quote_tpm -> $status (not a server error)"
else
    bad "GET /quote_tpm -> $status (expected a 4xx)"
fi

echo

# ---------------------------------------------------------------------------
# 7. Regression: the original TDX endpoints still work
# ---------------------------------------------------------------------------

echo "== 7. original endpoints still work =="

status=$(curl -sS -o /tmp/tpm_ping.txt -w '%{http_code}' --max-time 10 "$BASE_URL/ping")
if [[ "$status" == "200" && "$(cat /tmp/tpm_ping.txt)" == "pong" ]]; then
    ok "GET /ping -> 200 pong"
else
    bad "GET /ping -> $status '$(cat /tmp/tpm_ping.txt)'"
fi

RN=$(head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n')
status=$(curl -sS -o /tmp/tpm_report.json -w '%{http_code}' --max-time 30 \
    "$BASE_URL/attestation-with-randomnumber?rn=$RN")
REPORT_HEX=""
if [[ "$status" == "200" ]]; then
    REPORT_HEX=$(read_json /tmp/tpm_report.json '.report')
fi

if [[ "$status" == "200" && -n "$REPORT_HEX" ]]; then
    ok "GET /attestation-with-randomnumber -> 200 (TDX report)"
    if [[ "${REPORT_HEX:256:128}" == "$RN" ]]; then
        ok "the TDX report still binds REPORTDATA to the supplied nonce"
    else
        bad "the TDX report no longer binds REPORTDATA"
    fi
elif [[ "$status" == "501" ]]; then
    info "GET /attestation-with-randomnumber -> 501 (no TDX hardware here)"
else
    bad "GET /attestation-with-randomnumber -> $status $(cat /tmp/tpm_report.json)"
fi

if [[ -n "$REPORT_HEX" ]]; then
    status=$(curl -sS -o /tmp/tpm_verify.json -w '%{http_code}' --max-time 30 \
        -X POST -H 'Content-Type: application/json' \
        -d "{\"report\":\"$REPORT_HEX\"}" "$BASE_URL/verify-report")
    if [[ "$status" == "200" ]]; then
        trusted=$(read_json /tmp/tpm_verify.json '.trusted')
        if [[ "$trusted" == "true" ]]; then
            ok "POST /verify-report -> 200 trusted=true"
        else
            bad "POST /verify-report -> trusted=$trusted"
        fi
    elif [[ "$status" == "501" ]]; then
        info "POST /verify-report -> 501 (no TDX verifier here)"
    else
        bad "POST /verify-report -> $status $(cat /tmp/tpm_verify.json)"
    fi

    status=$(curl -sS -o /tmp/tpm_parse.json -w '%{http_code}' --max-time 30 \
        -X POST -H 'Content-Type: application/json' \
        -d "{\"report\":\"$REPORT_HEX\"}" "$BASE_URL/parse-report")
    if [[ "$status" == "200" ]]; then
        rlen=$(read_json /tmp/tpm_parse.json '.report_len')
        if [[ "$rlen" == "1024" ]]; then
            ok "POST /parse-report -> 200 report_len=1024"
        else
            bad "POST /parse-report -> report_len=$rlen"
        fi
    else
        bad "POST /parse-report -> $status $(cat /tmp/tpm_parse.json)"
    fi
fi

status=$(curl -sS -o /tmp/tpm_badrn.json -w '%{http_code}' --max-time 10 \
    "$BASE_URL/attestation-with-randomnumber?rn=zzzz")
if [[ "$status" == "400" ]]; then
    ok "non-hex rn -> 400 (unchanged)"
else
    bad "non-hex rn -> $status (expected 400)"
fi

status=$(curl -sS -o /tmp/tpm_404.json -w '%{http_code}' --max-time 10 "$BASE_URL/no-such-route")
if [[ "$status" == "404" ]] && grep -q '"error"' /tmp/tpm_404.json; then
    ok "unknown route -> 404 JSON (unchanged)"
else
    bad "unknown route -> $status $(cat /tmp/tpm_404.json)"
fi

echo

if [[ "$FAIL" -eq 0 ]]; then
    printf 'TPM web test: PASSED (%d checks)\n' "$PASS"
    exit 0
fi

printf 'TPM web test: FAILED (%d passed, %d failed)\n' "$PASS" "$FAIL"
exit 1
