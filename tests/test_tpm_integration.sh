#!/usr/bin/env bash
#
# TPM integration test: exercises the *real* TPM 2.0 simulator deployed in
# ./tpm-simu and the real TPM client library used by the server (tpm2-tools).
#
# It checks, in order:
#
#   1. the simulator is present and reports RUNNING (starting it if needed)
#   2. the simulator's own smoke test passes
#   3. the server's folder measurement unit tests pass (cargo test --lib)
#   4. a real folder digest is computed for TPM_MEASURE_DIR
#   5. that digest is extended into the configured PCR (PCR_Reset + PCR_Extend)
#   6. the PCR reads back a non-empty value that differs from the reset value
#   7. a real TPM quote is produced over that PCR, bound to a challenge
#   8. the quote's signature/message are non-empty and the challenge is bound
#   9. the quote verifies with the AK public part (tpm2_checkquote), and fails
#      for a different challenge
#
# Nothing here is mocked: every value comes from the simulator.
#
# Environment:
#   TPM_TCTI           TCTI string (default mssim:host=127.0.0.1,port=2321)
#   TPM_PCR_INDEX      PCR to use (default 16)
#   TPM_HASH_ALGORITHM hash bank (default sha256)
#   TPM_AK_HANDLE      persistent AK handle (default 0x81010002)
#   TPM_MEASURE_DIR    directory to measure (default <project>/src)
#
# The script exits 0 only if every check passes.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SIM_DIR="${TPM_SIMULATOR_DIR:-$PROJECT_DIR/tpm-simu}"

TCTI="${TPM_TCTI:-mssim:host=127.0.0.1,port=2321}"
PCR_INDEX="${TPM_PCR_INDEX:-16}"
HASH_ALG="${TPM_HASH_ALGORITHM:-sha256}"
AK_HANDLE="${TPM_AK_HANDLE:-0x81010002}"
MEASURE_DIR="${TPM_MEASURE_DIR:-$PROJECT_DIR/src}"

PASS=0
FAIL=0

ok()   { printf '  [PASS] %s\n' "$1"; PASS=$((PASS + 1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL + 1)); }
info() { printf '  [INFO] %s\n' "$1"; }

WORK="$(mktemp -d /tmp/tdx-tpm-int.XXXXXX)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

export TPM2TOOLS_TCTI="$TCTI"

tpm() { tpm2_"$@" 2>/dev/null; }

# Release the simulator's transient object slots. The simulator has very few,
# so a stale context from an earlier run makes every later command fail with
# "out of memory for object contexts".
flush_all() {
    for _ in $(seq 1 12); do
        tpm2_flushcontext -t >/dev/null 2>&1
    done
}

printf '==============================================\n'
printf ' TDX server - TPM integration test\n'
printf '==============================================\n'
printf 'simulator : %s\n' "$SIM_DIR"
printf 'tcti      : %s\n' "$TCTI"
printf 'pcr       : %s:%s\n' "$HASH_ALG" "$PCR_INDEX"
printf 'measure   : %s\n' "$MEASURE_DIR"
printf 'ak        : %s\n\n' "$AK_HANDLE"

# ---------------------------------------------------------------------------
# 1. simulator present and running
# ---------------------------------------------------------------------------

printf '[1] simulator status\n'
if [[ ! -x "$SIM_DIR/scripts/status.sh" ]]; then
    bad "$SIM_DIR/scripts/status.sh not found; the simulator deployment is missing"
    printf '\nTPM integration test: FAILED (no simulator)\n'
    exit 1
fi

STATUS_OUT="$("$SIM_DIR/scripts/status.sh" 2>&1 || true)"
if grep -q '^RUNNING' <<<"$STATUS_OUT"; then
    ok "simulator is already RUNNING"
else
    info "simulator is STOPPED; starting it"
    if "$SIM_DIR/scripts/start.sh" >/tmp/tdx-tpm-start.log 2>&1; then
        ok "scripts/start.sh started the simulator"
    else
        bad "scripts/start.sh failed"
        cat /tmp/tdx-tpm-start.log | sed 's/^/       /'
        printf '\nTPM integration test: FAILED (simulator start)\n'
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# 2. the simulator's own smoke test
# ---------------------------------------------------------------------------

printf '\n[2] simulator self test\n'
if "$SIM_DIR/scripts/test.sh" >/tmp/tdx-tpm-simtest.log 2>&1; then
    SUMMARY="$(grep -E 'Results:' /tmp/tdx-tpm-simtest.log | tail -1 | sed 's/^[[:space:]]*//')"
    ok "scripts/test.sh passed${SUMMARY:+ ($SUMMARY)}"
else
    bad "scripts/test.sh failed"
    tail -n 30 /tmp/tdx-tpm-simtest.log | sed 's/^/       /'
fi

if ! command -v tpm2_quote >/dev/null 2>&1; then
    bad "tpm2-tools is not installed; cannot talk to the TPM"
    printf '\nTPM integration test: FAILED (tpm2-tools missing)\n'
    exit 1
fi

if ! tpm2_startup -c >/dev/null 2>&1; then
    info "tpm2_startup reported a status (already started is fine)"
fi

# A TPM in DA (dictionary attack) lockout refuses every authorized command with
# 0x921, which would make this test fail for reasons unrelated to the code.
# Clearing the lockout is the documented recovery and is harmless on a
# simulator; it is best effort and never fails the test by itself.
flush_all
if command -v tpm2_dictionarylockout >/dev/null 2>&1 \
        && tpm2_dictionarylockout -c >/dev/null 2>&1; then
    info "cleared any DA lockout on the TPM"
fi

# ---------------------------------------------------------------------------
# 3. folder measurement unit tests
# ---------------------------------------------------------------------------

printf '\n[3] folder measurement tests\n'
if ( cd "$PROJECT_DIR" && cargo test --lib tpm:: >/tmp/tdx-tpm-cargotest.log 2>&1 ); then
    COUNT="$(grep -E '^test result:' /tmp/tdx-tpm-cargotest.log | tail -1)"
    ok "cargo test --lib tpm:: passed (${COUNT:-see log})"
else
    bad "cargo test --lib tpm:: failed"
    tail -n 40 /tmp/tdx-tpm-cargotest.log | sed 's/^/       /'
fi

# ---------------------------------------------------------------------------
# 4. a real folder digest
# ---------------------------------------------------------------------------

printf '\n[4] folder measurement\n'
if [[ ! -d "$MEASURE_DIR" ]]; then
    bad "measured directory $MEASURE_DIR does not exist"
fi

# Use the server's own implementation, so the shell test cannot drift from the
# Rust code and cannot silently pass with a different algorithm.
FOLDER_DIGEST="$(cd "$PROJECT_DIR" && cargo run --quiet --example measure_folder -- "$MEASURE_DIR" 2>/tmp/tdx-tpm-measure.log | tail -1)"

if [[ ${#FOLDER_DIGEST} -eq 64 ]]; then
    ok "server folder digest computed (${FOLDER_DIGEST:0:16}...)"
else
    bad "server could not measure $MEASURE_DIR"
    sed 's/^/       /' /tmp/tdx-tpm-measure.log
fi

# Measuring twice must give the same answer.
FOLDER_DIGEST_2="$(cd "$PROJECT_DIR" && cargo run --quiet --example measure_folder -- "$MEASURE_DIR" 2>/dev/null | tail -1)"
if [[ -n "$FOLDER_DIGEST" && "$FOLDER_DIGEST" == "$FOLDER_DIGEST_2" ]]; then
    ok "repeated measurement of the same directory is identical"
else
    bad "repeated measurement differs ($FOLDER_DIGEST vs $FOLDER_DIGEST_2)"
fi

# ---------------------------------------------------------------------------
# 5/6. PCR reset + extend + read
# ---------------------------------------------------------------------------

printf '\n[5] PCR reset + extend\n'
flush_all
if tpm2_pcrreset "$PCR_INDEX" >/dev/null 2>&1; then
    ok "PCR $PCR_INDEX reset"
else
    # A PCR that is already 0 still may refuse a reset on some TPMs; fall back
    # to reading it and requiring a known initial value.
    info "PCR $PCR_INDEX could not be reset (it may already be at its reset value)"
fi

# The folder digest is 32 bytes (64 hex chars), which is what a sha256 PCR
# extend expects. Fall back to a deterministic value if measurement failed.
EXTEND_VALUE="$FOLDER_DIGEST"
if [[ ${#EXTEND_VALUE} -ne 64 ]]; then
    EXTEND_VALUE="$(printf '%064d' 1)"
fi

if tpm2_pcrextend "$PCR_INDEX:$HASH_ALG=$EXTEND_VALUE" >/dev/null 2>&1; then
    ok "PCR $PCR_INDEX extended with the folder digest"
else
    bad "PCR $PCR_INDEX could not be extended"
fi

printf '\n[6] PCR read\n'
flush_all
tpm2_pcrread "$HASH_ALG:$PCR_INDEX" -o "$WORK/pcr.bin" >/dev/null 2>&1
PCR_VALUE="$(xxd -p "$WORK/pcr.bin" 2>/dev/null | tr -d '\n')"
if [[ -n "$PCR_VALUE" ]]; then
    ok "PCR $PCR_INDEX reads back a value (${PCR_VALUE:0:16}...)"
else
    bad "PCR $PCR_INDEX read returned nothing"
fi

if [[ -n "$PCR_VALUE" && "$PCR_VALUE" != "$(printf '0%.0s' $(seq 1 ${#PCR_VALUE}))" ]]; then
    ok "PCR value is not the reset value"
else
    bad "PCR value looks like the reset value; the extend did not take effect"
fi

# ---------------------------------------------------------------------------
# 7/8. real TPM quote
# ---------------------------------------------------------------------------

printf '\n[7] TPM quote\n'
CHALLENGE="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
AHANDLE="$AK_HANDLE"

flush_all
if ! tpm2_getcap handles-persistent 2>/dev/null | grep -qi "$(printf '%s' "$AK_HANDLE" | tr 'A-F' 'a-f')"; then
    info "no persistent AK at $AK_HANDLE; creating one"
    tpm2_createek -G rsa -c "$WORK/ek.ctx" -u "$WORK/ek.pub" >/dev/null 2>&1
    flush_all
    tpm2_createak -C "$WORK/ek.ctx" -c "$WORK/ak.ctx" -G rsa -g sha256 -s rsassa -u "$WORK/ak.pub" >/dev/null 2>&1
    flush_all
    if tpm2_evictcontrol -C o -c "$WORK/ak.ctx" "$AK_HANDLE" >/dev/null 2>&1; then
        ok "Attestation Key persisted at $AK_HANDLE"
    else
        bad "could not persist an Attestation Key at $AK_HANDLE"
        AHANDLE="$WORK/ak.ctx"
    fi
    flush_all
else
    ok "Attestation Key $AK_HANDLE is present"
fi

flush_all
tpm2_readpublic -c "$AHANDLE" -o "$WORK/ak.pem" -f pem >/dev/null 2>&1
if [[ -s "$WORK/ak.pem" ]]; then
    ok "Attestation Key public part exported ($(wc -c <"$WORK/ak.pem") bytes)"
else
    bad "could not export the Attestation Key public part"
fi

flush_all
if tpm2_quote -c "$AHANDLE" -g "$HASH_ALG" -l "$HASH_ALG:$PCR_INDEX" -q "$CHALLENGE" \
        -s "$WORK/quote.sig" -m "$WORK/quote.msg" -o "$WORK/quote.pcrs" >"$WORK/quote.log" 2>&1; then
    ok "tpm2_quote produced a quote"
else
    bad "tpm2_quote failed"
    tail -n 20 "$WORK/quote.log" | sed 's/^/       /'
fi

SIG_SIZE=$(wc -c <"$WORK/quote.sig" 2>/dev/null || echo 0)
MSG_SIZE=$(wc -c <"$WORK/quote.msg" 2>/dev/null || echo 0)
PCRS_SIZE=$(wc -c <"$WORK/quote.pcrs" 2>/dev/null || echo 0)

printf '\n[8] quote contents\n'
[[ "$SIG_SIZE" -gt 0 ]] && ok "signature is non-empty (${SIG_SIZE} bytes)" || bad "signature is empty"
[[ "$MSG_SIZE" -gt 0 ]] && ok "attestation message is non-empty (${MSG_SIZE} bytes)" || bad "attestation message is empty"
[[ "$PCRS_SIZE" -gt 0 ]] && ok "PCR digest blob is non-empty (${PCRS_SIZE} bytes)" || bad "PCR digest blob is empty"

# The challenge must be bound into the signed structure (TPMS_ATTEST.extraData).
if [[ -s "$WORK/quote.msg" ]] && xxd -p "$WORK/quote.msg" | tr -d '\n' | grep -qi "$CHALLENGE"; then
    ok "the challenge is bound into the quoted structure"
else
    bad "the challenge does not appear in the quoted structure"
fi

# ---------------------------------------------------------------------------
# 9. verify the quote against the AK public part
# ---------------------------------------------------------------------------

printf '\n[9] quote verification\n'
if [[ -s "$WORK/ak.pem" ]] && tpm2_checkquote -u "$WORK/ak.pem" -g "$HASH_ALG" \
        -m "$WORK/quote.msg" -s "$WORK/quote.sig" -q "$CHALLENGE" >/dev/null 2>&1; then
    ok "tpm2_checkquote accepts the quote for the correct challenge"
else
    bad "tpm2_checkquote rejected the quote"
fi

if tpm2_checkquote -u "$WORK/ak.pem" -g "$HASH_ALG" \
        -m "$WORK/quote.msg" -s "$WORK/quote.sig" -q "$(printf '00%.0s' $(seq 1 32))" >/dev/null 2>&1; then
    bad "tpm2_checkquote accepted a quote for the wrong challenge"
else
    ok "tpm2_checkquote rejects the quote for a wrong challenge"
fi

printf '\n==============================================\n'
if [[ "$FAIL" -eq 0 ]]; then
    printf ' TPM integration test: PASSED (%d checks)\n' "$PASS"
    exit 0
fi

printf ' TPM integration test: FAILED (%d passed, %d failed)\n' "$PASS" "$FAIL"
exit 1
