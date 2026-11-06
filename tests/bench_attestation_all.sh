#!/bin/sh
#
# bench_attestation_all.sh - 连续 N 次调用 POST /attestation_all 并统计耗时。
#
# 目标环境: Ubuntu 的 /bin/sh (dash) 或 bash, 只用 POSIX 语法, 不依赖 bash 专有特性。
#
# 用法:
#   sh tests/bench_attestation_all.sh           # 默认 100 次
#   sh tests/bench_attestation_all.sh 500       # 500 次
#   chmod +x tests/bench_attestation_all.sh && ./tests/bench_attestation_all.sh
#
# 环境变量:
#   WEB_BASE_URL   服务地址              默认 http://127.0.0.1:8000
#   COUNT          请求次数              默认 100 (第一个参数优先)
#   WARMUP         预热次数, 不计入统计    默认 0
#   NONCE_BYTES    nonce 字节数          默认 32 (即 64 个十六进制字符)
#   CURL_TIMEOUT   单请求总超时(秒)        默认 1800, 0 = 不限制
#                  对应 curl --max-time, 覆盖"服务端度量+签名+传输"全过程;
#                  度量的模型文件很大时要调大(GB 级目录可能几分钟到几十分钟)
#   CONNECT_TIMEOUT 建连超时(秒)          默认 10, 0 = 不限制
#                  对应 curl --connect-timeout, 与总超时分开: 服务没起时
#                  10 秒就报错, 不用等满 CURL_TIMEOUT
#   OUT_DIR        输出目录: 保存 timings.csv + 每个响应体
#   TIMING_DIR     服务端耗时 JSON 目录    默认 <项目根>/log/json
#   VERBOSE        1 = 打印第一次响应体    默认 0
#   QUIET          1 = 只打印失败与汇总    默认 0
#
# 说明:
#   * 每次请求都用新的 nonce, 因此没有一次会命中缓存, 每次都是完整的 TPM+TDX 流程;
#   * 统计的是客户端侧 time_total(含网络), 服务端逐段耗时在 $TIMING_DIR/*.json
#     (debug 构建才有), 字段含义见 docs/attestation-sample-record-fields.md;
#   * 设了 OUT_DIR 时, 保存下来的响应体可直接拿去 POST /verify_all。
#
# 退出码: 0 全部成功; 1 有失败请求; 2 环境或参数错误

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")

WEB_BASE_URL=${WEB_BASE_URL:-http://127.0.0.1:8000}
COUNT=${1:-${COUNT:-100}}
WARMUP=${WARMUP:-0}
NONCE_BYTES=${NONCE_BYTES:-32}
CURL_TIMEOUT=${CURL_TIMEOUT:-1800}
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-10}
OUT_DIR=${OUT_DIR:-}
TIMING_DIR=${TIMING_DIR:-$PROJECT_DIR/log/json}
VERBOSE=${VERBOSE:-0}
QUIET=${QUIET:-0}

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

# 结尾的 / 去掉, 避免出现 "//attestation_all"
WEB_BASE_URL=${WEB_BASE_URL%/}
ENDPOINT="$WEB_BASE_URL/attestation_all"

# --- 参数与环境检查 --------------------------------------------------------

case "$COUNT" in
    '' | *[!0-9]*) die "COUNT 必须是正整数, 当前为 '$COUNT'" ;;
esac
[ "$COUNT" -ge 1 ] || die "COUNT 必须 >= 1, 当前为 $COUNT"

case "$WARMUP" in
    '' | *[!0-9]*) die "WARMUP 必须是 >= 0 的整数, 当前为 '$WARMUP'" ;;
esac

case "$NONCE_BYTES" in
    '' | *[!0-9]*) die "NONCE_BYTES 必须是正整数, 当前为 '$NONCE_BYTES'" ;;
esac
# TPM 的 qualifyingData 上限是 64 字节
[ "$NONCE_BYTES" -ge 1 ] && [ "$NONCE_BYTES" -le 64 ] ||
    die "NONCE_BYTES 必须在 1..64 之间, 当前为 $NONCE_BYTES"

# 0 = 不限制(curl 语义), 也允许 0 是为了"大文件慢到无法预估"的场景
case "$CURL_TIMEOUT" in
    '' | *[!0-9]*) die "CURL_TIMEOUT 必须是 >= 0 的整数(0=不限制), 当前为 '$CURL_TIMEOUT'" ;;
esac
case "$CONNECT_TIMEOUT" in
    '' | *[!0-9]*) die "CONNECT_TIMEOUT 必须是 >= 0 的整数(0=不限制), 当前为 '$CONNECT_TIMEOUT'" ;;
esac
# 建连超时不该比总超时还长, 否则等于没设; 不报错, 顺手夹紧并提示。
if [ "$CURL_TIMEOUT" -ne 0 ] && [ "$CONNECT_TIMEOUT" -ne 0 ] && [ "$CONNECT_TIMEOUT" -gt "$CURL_TIMEOUT" ]; then
    printf 'note: CONNECT_TIMEOUT(%s) 大于 CURL_TIMEOUT(%s), 按 %s 处理\n' \
        "$CONNECT_TIMEOUT" "$CURL_TIMEOUT" "$CURL_TIMEOUT" >&2
    CONNECT_TIMEOUT=$CURL_TIMEOUT
fi

command -v curl >/dev/null 2>&1 || die "找不到 curl"
command -v od >/dev/null 2>&1 || die "找不到 od (coreutils)"
command -v awk >/dev/null 2>&1 || die "找不到 awk"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bench-attestation.XXXXXX") || die "mktemp 失败"
CSV="$WORK/timings.csv"
TIMES="$WORK/times.txt"
SORTED="$WORK/sorted.txt"

cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

printf 'iteration,http_code,time_total_s,success\n' >"$CSV"
: >"$TIMES"

# --- 工具函数 --------------------------------------------------------------

# 生成一个新的十六进制 nonce。
make_nonce() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "$NONCE_BYTES"
    else
        head -c "$NONCE_BYTES" /dev/urandom | od -An -tx1 | tr -d ' \n'
    fi
}

# 统计服务端耗时记录条数(目录不存在时为 0)。
count_records() {
    if [ -d "$TIMING_DIR" ]; then
        find "$TIMING_DIR" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l | tr -d ' '
    else
        printf '0'
    fi
}

# 人类可读的时长: 秒 -> "128 ms" / "3.4 s" / "2 m 08 s"。
# 大文件度量一次可能是几分钟, 纯毫秒数字很难读。
human_from_s() {
    awk -v s="${1:-0}" 'BEGIN {
        ms = s * 1000
        if (ms < 10000) printf "%d ms", int(ms + 0.5)
        else if (s < 60) printf "%.1f s", s
        else printf "%d m %02d s", int(s / 60), int(s % 60)
    }'
}

# 发一次请求。结果放在 R_CODE / R_SECONDS / R_SUCCESS / R_BODY / R_CURL_RC 里。
R_CODE=000
R_SECONDS=0
R_SUCCESS=0
R_BODY=''
R_CURL_RC=0

do_request() {
    _idx=$1
    R_CODE=000
    R_SECONDS=0
    R_SUCCESS=0
    R_CURL_RC=0
    R_BODY="$WORK/body-$_idx.json"
    _err="$WORK/err-$_idx.txt"

    _nonce=$(make_nonce) || return 1
    [ -n "$_nonce" ] || return 1

    # --max-time 覆盖"服务端度量+SHA-256+签名+传输"全过程, 大 model 目录要放长;
    # --connect-timeout 只管 TCP 建连, 服务没起时能立刻失败而不是空等 max-time。
    _metric=$(curl -sS \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$CURL_TIMEOUT" \
        -H 'Content-Type: application/json' \
        -d "{\"nonce\":\"$_nonce\"}" \
        -o "$R_BODY" \
        -w '%{http_code} %{time_total}' \
        "$ENDPOINT" 2>"$_err")
    _rc=$?
    R_CURL_RC=$_rc

    set -- $_metric
    R_CODE=${1:-000}
    R_SECONDS=${2:-0}

    # 成功 = HTTP 200 且响应体里 status 为 0(gpu-node 约定)
    if [ "$_rc" -eq 0 ] && [ "$R_CODE" = "200" ]; then
        if grep -Eq '"status"[[:space:]]*:[[:space:]]*0' "$R_BODY" 2>/dev/null; then
            R_SUCCESS=1
        fi
    fi
    return 0
}

# 失败的一句话原因: 区分"超时"和"连不上", 这两者的处理方式完全不同。
failure_reason() {
    case "$R_CURL_RC" in
        28) printf '超时' ;;
        6 | 7) printf '连不上' ;;
        0) printf 'http=%s' "$R_CODE" ;;
        *) printf 'curl-exit=%s' "$R_CURL_RC" ;;
    esac
}

# 打印失败原因: 响应体优先, 否则 curl 的 stderr。
print_failure_hint() {
    if [ -s "$R_BODY" ]; then
        printf '            body: %s\n' "$(head -c 200 "$R_BODY" | tr -d '\n')"
    elif [ -s "$_err" ]; then
        printf '            detail: %s\n' "$(head -n 1 "$_err")"
    fi
}

# 第 1 次就失败时判断是不是"再怎么试也没用", 是就带解决方案退出。
abort_if_hopeless() {
    case "$R_CURL_RC" in
        28)
            printf '\nerror: 第 1 次请求在 %ss 内没有返回(大模型目录的度量常见)\n' \
                "$CURL_TIMEOUT" >&2
            printf '       把总超时调大, 或设为 0 表示不限制:\n' >&2
            printf '       CURL_TIMEOUT=0 sh %s %s\n' "$0" "$COUNT" >&2
            exit 2
            ;;
        6 | 7)
            printf '\nerror: 连不上 %s\n' "$ENDPOINT" >&2
            if [ -s "$_err" ]; then
                head -n 2 "$_err" | sed 's/^/       /' >&2
            fi
            exit 2
            ;;
    esac
}

# --- 开跑 ------------------------------------------------------------------

printf 'target : %s\n' "$ENDPOINT"
printf 'count  : %s (warmup %s)\n' "$COUNT" "$WARMUP"
printf 'nonce  : %s bytes\n' "$NONCE_BYTES"
if [ "$CURL_TIMEOUT" = "0" ]; then _max_txt='不限制'; else _max_txt="${CURL_TIMEOUT}s"; fi
if [ "$CONNECT_TIMEOUT" = "0" ]; then _conn_txt='不限制'; else _conn_txt="${CONNECT_TIMEOUT}s"; fi
printf 'timeout: 单请求 %s, 建连 %s\n' "$_max_txt" "$_conn_txt"

RECORDS_BEFORE=$(count_records)
[ -n "$RECORDS_BEFORE" ] || RECORDS_BEFORE=0

i=1
while [ "$i" -le "$WARMUP" ]; do
    if do_request "warmup-$i"; then
        printf '[warmup %d/%d] %10s  %s\n' "$i" "$WARMUP" "$(human_from_s "$R_SECONDS")" \
            "$([ "$R_SUCCESS" -eq 1 ] && echo ok || echo "FAIL($(failure_reason))")"
        [ "$R_SUCCESS" -eq 1 ] || abort_if_hopeless
    else
        die "无法生成 nonce"
    fi
    i=$((i + 1))
done

ok=0
fail=0
i=1
while [ "$i" -le "$COUNT" ]; do
    if ! do_request "$i"; then
        die "无法生成 nonce"
    fi

    printf '%d,%s,%s,%d\n' "$i" "$R_CODE" "$R_SECONDS" "$R_SUCCESS" >>"$CSV"

    if [ "$R_SUCCESS" -eq 1 ]; then
        ok=$((ok + 1))
        printf '%s\n' "$R_SECONDS" >>"$TIMES"
        [ "$QUIET" = "1" ] || printf '[%3d/%3d] %10s  ok\n' "$i" "$COUNT" "$(human_from_s "$R_SECONDS")"
    else
        fail=$((fail + 1))
        printf '[%3d/%3d] %10s  FAIL (%s)\n' "$i" "$COUNT" \
            "$(human_from_s "$R_SECONDS")" "$(failure_reason)"

        # 只给前几次失败打印细节, 否则 100 条一样的错误会淹没汇总
        if [ "$fail" -le 3 ]; then
            print_failure_hint
        elif [ "$fail" -eq 4 ]; then
            printf '            (后续失败不再逐条展开)\n'
        fi

        # 第 1 次就超时/连不上, 后面 99 次只会重复失败。
        [ "$i" -eq 1 ] && abort_if_hopeless
    fi

    if [ "$i" -eq 1 ] && [ "$VERBOSE" = "1" ] && [ -s "$R_BODY" ]; then
        if command -v jq >/dev/null 2>&1; then
            jq . "$R_BODY" | head -n 40
        else
            head -c 800 "$R_BODY"
            printf '\n'
        fi
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
printf '请求次数    : %s (warmup %s)\n' "$COUNT" "$WARMUP"
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
    # 慢到分钟级时再给一行人话, 免得对着六位数毫秒换算
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
    printf '              逐段耗时见该目录下的 JSON, 字段说明见\n'
    printf '              docs/attestation-sample-record-fields.md\n'
else
    printf '服务端记录  : 未发现新增 ( %s )\n' "$TIMING_DIR"
    printf '              若服务端是 release 构建则不会产生耗时 JSON;\n'
    printf '              否则检查 TDX_TIMING_DIR 是否指向了别处。\n'
fi

if [ -n "$OUT_DIR" ]; then
    mkdir -p "$OUT_DIR" || die "无法创建输出目录 $OUT_DIR"
    cp "$CSV" "$OUT_DIR/timings.csv"
    i=1
    saved=0
    while [ "$i" -le "$COUNT" ]; do
        if [ -s "$WORK/body-$i.json" ]; then
            cp "$WORK/body-$i.json" "$OUT_DIR/resp-$i.json"
            saved=$((saved + 1))
        fi
        i=$((i + 1))
    done
    printf '输出        : %s (timings.csv + %s 个响应体, 可直接 POST /verify_all)\n' \
        "$OUT_DIR" "$saved"
else
    printf '输出        : 明细未保存 (设 OUT_DIR=目录 可保存 timings.csv 和响应体)\n'
fi

[ "$fail" -eq 0 ] || exit 1
exit 0
