#!/bin/sh
#
# bench_verify_all.sh - 连续 N 次调用验证接口，量它的开销。
#
# 目标环境: Ubuntu 的 /bin/sh (dash) 或 bash, 只用 POSIX 语法, 不依赖 bash 专有特性。
#
# 验证是**无状态**的: 同一份证明可以反复提交, 每次都重新走一遍
# "hex 解码 -> TDX module 重算 MAC -> tpm2_checkquote 离线验签"。
# 所以先用 /attestation_all 取一份证明, 再把它重放 N 次, 得到的就是纯验证开销,
# 不含目录度量那一段。
#
# 用法:
#   sh tests/bench_verify_all.sh                # 取一份证明, 再验证 100 次
#   sh tests/bench_verify_all.sh 500            # 500 次
#   PROOF=out/resp-1.json sh tests/bench_verify_all.sh   # 用之前存下的证明
#   ROUTE=verify-report sh tests/bench_verify_all.sh     # 只测 TDX 报告校验
#
# 环境变量:
#   WEB_BASE_URL    服务地址              默认 http://127.0.0.1:8000
#   COUNT           验证次数              默认 100 (第一个参数优先)
#   WARMUP          预热次数, 不计入统计    默认 0
#   PROOF           现成的 /attestation_all 响应文件; 不给就先请求一份
#   PROOF_OUT       把本次取到的证明另存一份, 供下次 PROOF= 复用
#   ROUTE           verify_all | verify-report   默认 verify_all
#   CURL_TIMEOUT    单请求总超时(秒)        默认 120, 0 = 不限制
#   CONNECT_TIMEOUT 建连超时(秒)           默认 10, 0 = 不限制
#   TIMING_DIR      服务端耗时 JSON 目录    默认 <项目根>/log/json
#   OUT_DIR         保存 timings.csv        默认只打印不落盘
#   VERBOSE         1 = 打印第一次响应体     默认 0
#   QUIET           1 = 只打印失败与汇总     默认 0
#
# 说明:
#   * 验证不需要新 nonce, 也不消耗任何东西, 所以重放同一份证明是合法的;
#     想验证"不同 challenge 也都能过", 请用 make bench + 逐条 verify;
#   * ROUTE=verify-report 只测 TDX 模块那一次 ioctl, 用来把 TPM 验签的开销
#     单独摘出去 (它需要 jq 从证明里取出 evidence.tdx.report);
#   * 服务端逐段耗时见 $TIMING_DIR/*.json (debug 构建), 聚合用 make timing-csv。
#
# 退出码: 0 全部成功; 1 有失败请求; 2 环境或参数错误

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")

WEB_BASE_URL=${WEB_BASE_URL:-http://127.0.0.1:8000}
COUNT=${1:-${COUNT:-100}}
WARMUP=${WARMUP:-0}
PROOF=${PROOF:-}
PROOF_OUT=${PROOF_OUT:-}
ROUTE=${ROUTE:-verify_all}
CURL_TIMEOUT=${CURL_TIMEOUT:-120}
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-10}
TIMING_DIR=${TIMING_DIR:-$PROJECT_DIR/log/json}
OUT_DIR=${OUT_DIR:-}
VERBOSE=${VERBOSE:-0}
QUIET=${QUIET:-0}
NONCE_BYTES=32

usage() {
    sed -n '3,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 2
}

case "${1:-}" in
    -h | --help) usage ;;
esac

WEB_BASE_URL=${WEB_BASE_URL%/}
ATTEST_URL="$WEB_BASE_URL/attestation_all"
VERIFY_URL="$WEB_BASE_URL/$ROUTE"

# --- 参数与环境检查 --------------------------------------------------------

case "$COUNT" in
    '' | *[!0-9]*) die "COUNT 必须是正整数, 当前为 '$COUNT'" ;;
esac
[ "$COUNT" -ge 1 ] || die "COUNT 必须 >= 1, 当前为 $COUNT"

case "$WARMUP" in
    '' | *[!0-9]*) die "WARMUP 必须是 >= 0 的整数, 当前为 '$WARMUP'" ;;
esac

case "$CURL_TIMEOUT" in
    '' | *[!0-9]*) die "CURL_TIMEOUT 必须是 >= 0 的整数(0=不限制), 当前为 '$CURL_TIMEOUT'" ;;
esac
case "$CONNECT_TIMEOUT" in
    '' | *[!0-9]*) die "CONNECT_TIMEOUT 必须是 >= 0 的整数(0=不限制), 当前为 '$CONNECT_TIMEOUT'" ;;
esac
if [ "$CURL_TIMEOUT" -ne 0 ] && [ "$CONNECT_TIMEOUT" -ne 0 ] && [ "$CONNECT_TIMEOUT" -gt "$CURL_TIMEOUT" ]; then
    printf 'note: CONNECT_TIMEOUT(%s) 大于 CURL_TIMEOUT(%s), 按 %s 处理\n' \
        "$CONNECT_TIMEOUT" "$CURL_TIMEOUT" "$CURL_TIMEOUT" >&2
    CONNECT_TIMEOUT=$CURL_TIMEOUT
fi

case "$ROUTE" in
    verify_all | verify-report) ;;
    *) die "ROUTE 只能是 verify_all 或 verify-report, 当前为 '$ROUTE'" ;;
esac

command -v curl >/dev/null 2>&1 || die "找不到 curl"
command -v od >/dev/null 2>&1 || die "找不到 od (coreutils)"
command -v awk >/dev/null 2>&1 || die "找不到 awk"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bench-verify.XXXXXX") || die "mktemp 失败"
CSV="$WORK/timings.csv"
TIMES="$WORK/times.txt"
SORTED="$WORK/sorted.txt"
BODY="$WORK/body.json"
PROOF_FILE="$WORK/proof.json"
ERR="$WORK/err.txt"

cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

printf 'iteration,http_code,time_total_s,success\n' >"$CSV"
: >"$TIMES"

# --- 工具函数 --------------------------------------------------------------

make_nonce() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$NONCE_BYTES"
    else
        head -c "$NONCE_BYTES" /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

count_records() {
    if [ -d "$TIMING_DIR" ]; then
        find "$TIMING_DIR" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l | tr -d ' '
    else
        printf '0'
    fi
}

# 人类可读的时长: 秒 -> "128 ms" / "3.4 s" / "2 m 08 s"。
human_from_s() {
    awk -v s="${1:-0}" 'BEGIN {
        ms = s * 1000
        if (ms < 10000) printf "%d ms", int(ms + 0.5)
        else if (s < 60) printf "%.1f s", s
        else printf "%d m %02d s", int(s / 60), int(s % 60)
    }'
}

bytes_of() {
    wc -c <"$1" 2>/dev/null | tr -d ' '
}

# --- 准备请求体 ------------------------------------------------------------

# 1) 拿到一份证明 (要么用 PROOF, 要么现场请求一份)。
if [ -n "$PROOF" ]; then
    [ -f "$PROOF" ] || die "PROOF 文件不存在: $PROOF"
    [ -s "$PROOF" ] || die "PROOF 文件是空的: $PROOF"
    cp "$PROOF" "$PROOF_FILE"
    printf 'proof  : %s (%s 字节, 直接复用)\n' "$PROOF" "$(bytes_of "$PROOF_FILE")"
else
    printf 'proof  : 未提供 PROOF, 先请求一份证明'
    printf ' (会跑一次完整的度量, 大目录可能较慢)\n'
    _nonce=$(make_nonce) || die "无法生成 nonce"
    _code=$(
        curl -sS \
            --connect-timeout "$CONNECT_TIMEOUT" \
            --max-time 0 \
            -H 'Content-Type: application/json' \
            -d "{\"nonce\":\"$_nonce\"}" \
            -o "$PROOF_FILE" \
            -w '%{http_code}' \
            "$ATTEST_URL" 2>"$ERR"
    )
    _rc=$?
    [ "$_rc" -eq 0 ] || {
        printf '\nerror: 取证明失败 (curl exit %s)\n' "$_rc" >&2
        [ -s "$ERR" ] && head -n 2 "$ERR" | sed 's/^/       /' >&2
        exit 2
    }
    [ "$_code" = "200" ] || {
        printf '\nerror: 取证明返回 http=%s\n' "$_code" >&2
        [ -s "$PROOF_FILE" ] && head -c 300 "$PROOF_FILE" | tr -d '\n' | sed 's/^/       /' >&2
        printf '\n' >&2
        exit 2
    }
    printf '         已取得 %s 字节\n' "$(bytes_of "$PROOF_FILE")"
    if [ -n "$PROOF_OUT" ]; then
        cp "$PROOF_FILE" "$PROOF_OUT" 2>/dev/null ||
            printf 'warning: 无法写入 PROOF_OUT=%s\n' "$PROOF_OUT" >&2
        printf '         已另存到 %s (下次可直接 PROOF=%s)\n' "$PROOF_OUT" "$PROOF_OUT"
    fi
fi

# 证明本身必须带 tdx 分片，否则 verify_all 只会回 400。
grep -q '"evidence"' "$PROOF_FILE" 2>/dev/null ||
    die "$PROOF 看起来不是 /attestation_all 的响应 (没有 evidence 字段)"
grep -q '"tdx"' "$PROOF_FILE" 2>/dev/null ||
    die "$PROOF 缺少 evidence.tdx, /verify_all 会直接 400"

# 2) 按 ROUTE 生成真正的请求体。
if [ "$ROUTE" = "verify-report" ]; then
    command -v jq >/dev/null 2>&1 ||
        die "ROUTE=verify-report 需要 jq 来从证明里取出 evidence.tdx.report"
    _report=$(jq -r '.evidence.tdx.report // empty' "$PROOF_FILE" 2>/dev/null)
    [ -n "$_report" ] || die "无法从证明里取到 evidence.tdx.report"
    printf '{"report":"%s"}' "$_report" >"$BODY"
else
    cp "$PROOF_FILE" "$BODY"
fi

# --- 发一次验证请求 --------------------------------------------------------

R_CODE=000
R_SECONDS=0
R_SUCCESS=0
R_CURL_RC=0
R_BODY=''
R_TRUSTED=''

do_request() {
    _idx=$1
    R_CODE=000
    R_SECONDS=0
    R_SUCCESS=0
    R_CURL_RC=0
    R_BODY="$WORK/resp-$_idx.json"

    _metric=$(curl -sS \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$CURL_TIMEOUT" \
        -H 'Content-Type: application/json' \
        --data-binary "@$BODY" \
        -o "$R_BODY" \
        -w '%{http_code} %{time_total}' \
        "$VERIFY_URL" 2>"$ERR")
    _rc=$?
    R_CURL_RC=$_rc

    set -- $_metric
    R_CODE=${1:-000}
    R_SECONDS=${2:-0}

    R_TRUSTED=''
    if [ "$_rc" -eq 0 ] && [ "$R_CODE" = "200" ]; then
        # verify_all 回 {"trusted":true,"tpm_trusted":...,"tdx_trusted":...}；
        # 注意 "tpm_trusted" 里不含子串 "trusted"（前面是下划线），所以不会误匹配。
        if grep -Eq '"trusted"[[:space:]]*:[[:space:]]*true' "$R_BODY" 2>/dev/null; then
            R_SUCCESS=1
        fi
        R_TRUSTED=$(grep -Eo '"trusted"[[:space:]]*:[[:space:]]*(true|false)' "$R_BODY" 2>/dev/null |
            head -n 1 | tr -d ' ')
    fi
    return 0
}

failure_reason() {
    case "$R_CURL_RC" in
        28) printf '超时' ;;
        6 | 7) printf '连不上' ;;
        0) printf 'http=%s' "$R_CODE" ;;
        *) printf 'curl-exit=%s' "$R_CURL_RC" ;;
    esac
}

print_failure_hint() {
    if [ -s "$R_BODY" ]; then
        printf '            body: %s\n' "$(head -c 200 "$R_BODY" | tr -d '\n')"
    elif [ -s "$ERR" ]; then
        printf '            detail: %s\n' "$(head -n 1 "$ERR")"
    fi
}

abort_if_hopeless() {
    case "$R_CURL_RC" in
        28)
            printf '\nerror: 第 1 次验证在 %ss 内没有返回\n' "$CURL_TIMEOUT" >&2
            printf '       验证不含目录度量, 正常应在百毫秒级; 先确认服务端是不是卡住了:\n' >&2
            printf '       CURL_TIMEOUT=0 sh %s %s\n' "$0" "$COUNT" >&2
            exit 2
            ;;
        6 | 7)
            printf '\nerror: 连不上 %s\n' "$VERIFY_URL" >&2
            if [ -s "$ERR" ]; then
                head -n 2 "$ERR" | sed 's/^/       /' >&2
            fi
            exit 2
            ;;
    esac
}

# --- 开跑 ------------------------------------------------------------------

printf 'target : %s\n' "$VERIFY_URL"
printf 'body   : %s 字节 (%s)\n' "$(bytes_of "$BODY")" "$ROUTE"
printf 'count  : %s (warmup %s)\n' "$COUNT" "$WARMUP"
if [ "$CURL_TIMEOUT" = "0" ]; then _max_txt='不限制'; else _max_txt="${CURL_TIMEOUT}s"; fi
if [ "$CONNECT_TIMEOUT" = "0" ]; then _conn_txt='不限制'; else _conn_txt="${CONNECT_TIMEOUT}s"; fi
printf 'timeout: 单请求 %s, 建连 %s\n' "$_max_txt" "$_conn_txt"

RECORDS_BEFORE=$(count_records)
[ -n "$RECORDS_BEFORE" ] || RECORDS_BEFORE=0

i=1
while [ "$i" -le "$WARMUP" ]; do
    do_request "warmup-$i"
    printf '[warmup %d/%d] %10s  %s\n' "$i" "$WARMUP" "$(human_from_s "$R_SECONDS")" \
        "$([ "$R_SUCCESS" -eq 1 ] && echo ok || echo "FAIL($(failure_reason))")"
    [ "$R_SUCCESS" -eq 1 ] || abort_if_hopeless
    i=$((i + 1))
done

ok=0
fail=0
i=1
while [ "$i" -le "$COUNT" ]; do
    do_request "$i"

    printf '%d,%s,%s,%d\n' "$i" "$R_CODE" "$R_SECONDS" "$R_SUCCESS" >>"$CSV"

    if [ "$R_SUCCESS" -eq 1 ]; then
        ok=$((ok + 1))
        printf '%s\n' "$R_SECONDS" >>"$TIMES"
        [ "$QUIET" = "1" ] || printf '[%3d/%3d] %10s  ok\n' "$i" "$COUNT" "$(human_from_s "$R_SECONDS")"
    else
        fail=$((fail + 1))
        printf '[%3d/%3d] %10s  FAIL (%s%s)\n' "$i" "$COUNT" \
            "$(human_from_s "$R_SECONDS")" "$(failure_reason)" \
            "$([ -n "$R_TRUSTED" ] && echo ", $R_TRUSTED")"

        if [ "$fail" -le 3 ]; then
            print_failure_hint
        elif [ "$fail" -eq 4 ]; then
            printf '            (后续失败不再逐条展开)\n'
        fi

        [ "$i" -eq 1 ] && abort_if_hopeless
    fi

    if [ "$i" -eq 1 ] && [ "$VERBOSE" = "1" ] && [ -s "$R_BODY" ]; then
        printf 'first response: %s\n' "$(head -c 300 "$R_BODY" | tr -d '\n')"
    fi

    i=$((i + 1))
done

RECORDS_AFTER=$(count_records)
[ -n "$RECORDS_AFTER" ] || RECORDS_AFTER=0
RECORDS_NEW=$((RECORDS_AFTER - RECORDS_BEFORE))

# --- 汇总 ------------------------------------------------------------------

T_MIN=0
T_MEAN=0
T_P50=0
T_P90=0
T_P99=0
T_MAX=0

if [ -s "$TIMES" ]; then
    sort -n "$TIMES" >"$SORTED"
    set -- $(awk '
        function pct(p,   i, x) {
            x = p * n
            i = int(x)
            if (x > i) i++
            if (i < 1) i = 1
            if (i > n) i = n
            return v[i]
        }
        { v[++n] = $1 * 1000; s += $1 * 1000 }
        END {
            if (n == 0) { print 0, 0, 0, 0, 0, 0; exit }
            printf "%.1f %.1f %.1f %.1f %.1f %.1f\n", v[1], s / n, pct(0.50), pct(0.90), pct(0.99), v[n]
        }
    ' "$SORTED")
    T_MIN=${1:-0}
    T_MEAN=${2:-0}
    T_P50=${3:-0}
    T_P90=${4:-0}
    T_P99=${5:-0}
    T_MAX=${6:-0}
fi

printf '\n================ 汇总 ================\n'
printf '接口        : %s\n' "$VERIFY_URL"
printf '证明体大小  : %s 字节\n' "$(bytes_of "$BODY")"
printf '验证次数    : %s (warmup %s)\n' "$COUNT" "$WARMUP"
printf '成功 / 失败 : %s / %s\n' "$ok" "$fail"
if [ "$fail" -gt 0 ]; then
    printf '失败码分布  : '
    awk -F, 'NR > 1 && $4 == 0 { print $2 }' "$CSV" | sort | uniq -c |
        awk '{ printf "%s×%s  ", $2, $1 }'
    printf '\n'
fi
if [ "$ok" -gt 0 ]; then
    printf '客户端耗时  : min %s  mean %s  p50 %s  p90 %s  p99 %s  max %s (ms)\n' \
        "$T_MIN" "$T_MEAN" "$T_P50" "$T_P90" "$T_P99" "$T_MAX"
    awk -v p="$T_P50" -v m="$T_MAX" '
        function h(ms,   s) {
            if (ms < 1000) return sprintf("%d ms", int(ms + 0.5))
            s = ms / 1000
            if (s < 60) return sprintf("%.1f s", s)
            return sprintf("%d m %02d s", int(s / 60), int(s % 60))
        }
        BEGIN {
            if (p + 0 >= 1000)
                printf "              约: p50 %s, max %s\n", h(p), h(m)
        }
    '
fi

if [ "$RECORDS_NEW" -gt 0 ]; then
    printf '服务端记录  : +%s 条 ( %s )\n' "$RECORDS_NEW" "$TIMING_DIR"
    printf '              逐段耗时见该目录下的 JSON, 聚合用:\n'
    printf '              python3 tools/summarize_timing.py %s -o log/json/summary.csv\n' "$TIMING_DIR"
else
    printf '服务端记录  : 未发现新增 ( %s )\n' "$TIMING_DIR"
    printf '              若服务端是 release 构建则不会产生耗时 JSON;\n'
    printf '              否则检查 TDX_TIMING_DIR 是否指向了别处。\n'
fi

if [ -n "$OUT_DIR" ]; then
    mkdir -p "$OUT_DIR" || die "无法创建输出目录 $OUT_DIR"
    cp "$CSV" "$OUT_DIR/verify-timings.csv"
    printf '输出        : %s/verify-timings.csv\n' "$OUT_DIR"
else
    printf '输出        : 明细未保存 (设 OUT_DIR=目录 可保存 verify-timings.csv)\n'
fi

[ "$fail" -eq 0 ] || exit 1
exit 0
