#!/bin/sh
#
# bench_gpu_attest.sh - 连续 N 次调用 GET /gpu-attestation，量"生成 GPU 报告"的耗时。
#
# 目标环境: Ubuntu 的 /bin/sh (dash) 或 bash, 只用 POSIX 语法, 不依赖 bash 专有特性。
#
# 每一条请求都会真的起一个子进程 (`sh gpu_local_attest.sh` -> 预编译的 `nvattest`),
# 所以测到的就是 NVIDIA SDK 跑一遍的完整时间: 采集 + 证书链 + OCSP + RIM 比对。
# 服务端同一时刻只跑一个 GPU 脚本? 不是 —— 每个请求各起一个进程, 并发会互相抢 CPU,
# 想测单次成本就保持串行 (本脚本默认就是串行)。
#
# 用法:
#   sh tests/bench_gpu_attest.sh            # 默认 20 次
#   sh tests/bench_gpu_attest.sh 50         # 50 次
#
# 环境变量:
#   WEB_BASE_URL    服务地址              默认 http://127.0.0.1:8000
#   COUNT           请求次数              默认 20 (第一个参数优先)
#   WARMUP          预热次数, 不计入统计    默认 1
#   CURL_TIMEOUT    单请求超时(秒)         默认 300, 0 = 不限制
#   CONNECT_TIMEOUT 建连超时(秒)           默认 10, 0 = 不限制
#   TIMING_DIR      服务端耗时 JSON 目录    默认 <项目根>/log/json
#   OUT_DIR         保存 gpu-timings.csv   默认只打印不落盘
#   VERBOSE         1 = 打印第一次响应体     默认 0
#   QUIET           1 = 只打印失败与汇总     默认 0
#
# 说明:
#   * 每次请求都会重新跑一遍 SDK, 里面有 OCSP 联网查询, 所以耗时不全是本地计算;
#     默认 20 次而不是 100 次, 避免把对端 OCSP 打太狠, 也避免自己等太久;
#   * 成功 = HTTP 200 (说明脚本跑完且输出可解析); 证明结论另算:
#     `successful:true/false` 是从 SDK 打印的文本里刮出来的, 仅供参考
#     (负结论若写成 "unsuccessful"/"not successful", 会被误判为 true, 见 src/gpu.rs:378);
#   * 服务端 debug 构建会在 $TIMING_DIR 里落一条 route=/gpu-attestation 的记录,
#     `gpu_script_us` 就是这一步(拿报告)的耗时, `gpu_parse_us` 是文本解析, 用
#     make timing-csv 聚合。
#
# 退出码: 0 全部成功且结论为 true; 1 有失败请求或结论为 false; 2 环境或参数错误

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(dirname -- "$SCRIPT_DIR")

WEB_BASE_URL=${WEB_BASE_URL:-http://127.0.0.1:8000}
COUNT=${1:-${COUNT:-20}}
WARMUP=${WARMUP:-1}
CURL_TIMEOUT=${CURL_TIMEOUT:-300}
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-10}
TIMING_DIR=${TIMING_DIR:-$PROJECT_DIR/log/json}
OUT_DIR=${OUT_DIR:-}
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

WEB_BASE_URL=${WEB_BASE_URL%/}
ENDPOINT="$WEB_BASE_URL/gpu-attestation"

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

command -v curl >/dev/null 2>&1 || die "找不到 curl"
command -v awk >/dev/null 2>&1 || die "找不到 awk"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bench-gpu.XXXXXX") || die "mktemp 失败"
CSV="$WORK/timings.csv"
TIMES="$WORK/times.txt"
SORTED="$WORK/sorted.txt"
ERR="$WORK/err.txt"

cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT HUP INT TERM

printf 'iteration,http_code,time_total_s,http_ok,attest_ok\n' >"$CSV"
: >"$TIMES"

# --- 工具函数 --------------------------------------------------------------

count_records() {
    if [ -d "$TIMING_DIR" ]; then
        find "$TIMING_DIR" -maxdepth 1 -type f -name '*.json' 2>/dev/null | wc -l | tr -d ' '
    else
        printf '0'
    fi
}

human_from_s() {
    awk -v s="${1:-0}" 'BEGIN {
        ms = s * 1000
        if (ms < 10000) printf "%d ms", int(ms + 0.5)
        else if (s < 60) printf "%.1f s", s
        else printf "%d m %02d s", int(s / 60), int(s % 60)
    }'
}

# --- 发一次请求 ------------------------------------------------------------

R_CODE=000        # HTTP 状态码
R_SECONDS=0       # curl 的 time_total
R_HTTP_OK=0       # HTTP 层成功(计时有效)
R_ATTEST_OK=-1    # 证明结论: 1=true, 0=false, -1=没解析出来
R_CURL_RC=0
R_BODY=''

do_request() {
    _idx=$1
    R_CODE=000
    R_SECONDS=0
    R_HTTP_OK=0
    R_ATTEST_OK=-1
    R_CURL_RC=0
    R_BODY="$WORK/resp-$_idx.json"

    _metric=$(curl -sS \
        --connect-timeout "$CONNECT_TIMEOUT" \
        --max-time "$CURL_TIMEOUT" \
        -o "$R_BODY" \
        -w '%{http_code} %{time_total}' \
        "$ENDPOINT" 2>"$ERR")
    _rc=$?
    R_CURL_RC=$_rc

    set -- $_metric
    R_CODE=${1:-000}
    R_SECONDS=${2:-0}

    if [ "$_rc" -eq 0 ] && [ "$R_CODE" = "200" ]; then
        R_HTTP_OK=1
        if grep -Eq '"successful"[[:space:]]*:[[:space:]]*true' "$R_BODY" 2>/dev/null; then
            R_ATTEST_OK=1
        elif grep -Eq '"successful"[[:space:]]*:[[:space:]]*false' "$R_BODY" 2>/dev/null; then
            R_ATTEST_OK=0
        fi
    fi
    return 0
}

failure_reason() {
    case "$R_CURL_RC" in
        28) printf '超时' ;;
        6 | 7) printf '连不上' ;;
        0)
            case "$R_CODE" in
                501) printf 'http=501 脚本缺失/不可执行' ;;
                500) printf 'http=500 nvattest 非零退出' ;;
                *) printf 'http=%s' "$R_CODE" ;;
            esac
            ;;
        *) printf 'curl-exit=%s' "$R_CURL_RC" ;;
    esac
}

verdict_text() {
    case "$R_ATTEST_OK" in
        1) printf 'attest=true' ;;
        0) printf 'attest=false' ;;
        *) printf 'attest=?' ;;
    esac
}

print_failure_hint() {
    if [ -s "$R_BODY" ]; then
        printf '            body: %s\n' "$(head -c 300 "$R_BODY" | tr -d '\n')"
    elif [ -s "$ERR" ]; then
        printf '            detail: %s\n' "$(head -n 1 "$ERR")"
    fi
}

# 第 1 次就失败的"没救了"情形: 直接给排查方向。
abort_if_hopeless() {
    case "$R_CURL_RC" in
        28)
            printf '\nerror: 第 1 次请求在 %ss 内没有返回\n' "$CURL_TIMEOUT" >&2
            printf '       GPU 证明要跑一遍 SDK(含 OCSP 联网), 冷启动可能很慢:\n' >&2
            printf '       CURL_TIMEOUT=0 sh %s %s\n' "$0" "$COUNT" >&2
            exit 2
            ;;
        6 | 7)
            printf '\nerror: 连不上 %s\n' "$ENDPOINT" >&2
            if [ -s "$ERR" ]; then
                head -n 2 "$ERR" | sed 's/^/       /' >&2
            fi
            exit 2
            ;;
        0)
            if [ "$R_CODE" = "501" ]; then
                printf '\nerror: /gpu-attestation 返回 501\n' >&2
                printf '       gpu-attest 下的脚本不存在或不可执行, 检查:\n' >&2
                printf '       ls -l gpu-attest/gpu_local_attest.sh gpu-attest/nvattest\n' >&2
                printf '       以及 GPU_ATTEST_SCRIPT 是否指向了别处\n' >&2
                exit 2
            fi
            ;;
    esac
}

# --- 开跑 ------------------------------------------------------------------

printf 'target : %s\n' "$ENDPOINT"
printf 'count  : %s (warmup %s)\n' "$COUNT" "$WARMUP"
if [ "$CURL_TIMEOUT" = "0" ]; then _max_txt='不限制'; else _max_txt="${CURL_TIMEOUT}s"; fi
if [ "$CONNECT_TIMEOUT" = "0" ]; then _conn_txt='不限制'; else _conn_txt="${CONNECT_TIMEOUT}s"; fi
printf 'timeout: 单请求 %s, 建连 %s\n' "$_max_txt" "$_conn_txt"
printf 'note   : 每请求都会真跑一次 nvattest(含 OCSP 联网查询)\n'

RECORDS_BEFORE=$(count_records)
[ -n "$RECORDS_BEFORE" ] || RECORDS_BEFORE=0

i=1
while [ "$i" -le "$WARMUP" ]; do
    do_request "warmup-$i"
    printf '[warmup %d/%d] %10s  %s\n' "$i" "$WARMUP" "$(human_from_s "$R_SECONDS")" \
        "$([ "$R_HTTP_OK" -eq 1 ] && echo ok || echo "FAIL($(failure_reason))")"
    [ "$R_HTTP_OK" -eq 1 ] || abort_if_hopeless
    i=$((i + 1))
done

ok=0
fail=0
attest_true=0
attest_false=0
attest_unknown=0
i=1
while [ "$i" -le "$COUNT" ]; do
    do_request "$i"

    printf '%d,%s,%s,%d,%s\n' "$i" "$R_CODE" "$R_SECONDS" "$R_HTTP_OK" "$R_ATTEST_OK" >>"$CSV"

    if [ "$R_HTTP_OK" -eq 1 ]; then
        ok=$((ok + 1))
        printf '%s\n' "$R_SECONDS" >>"$TIMES"
        case "$R_ATTEST_OK" in
            1) attest_true=$((attest_true + 1)) ;;
            0) attest_false=$((attest_false + 1)) ;;
            *) attest_unknown=$((attest_unknown + 1)) ;;
        esac
        [ "$QUIET" = "1" ] ||
            printf '[%3d/%3d] %10s  ok  (%s)\n' "$i" "$COUNT" \
                "$(human_from_s "$R_SECONDS")" "$(verdict_text)"
    else
        fail=$((fail + 1))
        printf '[%3d/%3d] %10s  FAIL (%s)\n' "$i" "$COUNT" \
            "$(human_from_s "$R_SECONDS")" "$(failure_reason)"

        if [ "$fail" -le 3 ]; then
            print_failure_hint
        elif [ "$fail" -eq 4 ]; then
            printf '            (后续失败不再逐条展开)\n'
        fi

        [ "$i" -eq 1 ] && abort_if_hopeless
    fi

    if [ "$i" -eq 1 ] && [ "$VERBOSE" = "1" ] && [ -s "$R_BODY" ]; then
        printf 'first response: %s\n' "$(head -c 400 "$R_BODY" | tr -d '\n')"
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
printf '接口        : %s\n' "$ENDPOINT"
printf '请求次数    : %s (warmup %s)\n' "$COUNT" "$WARMUP"
printf '成功 / 失败 : %s / %s   (HTTP 层, 决定计时是否有效)\n' "$ok" "$fail"
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
    printf '证明结论    : true %s / false %s / 未解析 %s\n' \
        "$attest_true" "$attest_false" "$attest_unknown"
    if [ "$attest_false" -gt 0 ]; then
        printf '              ! SDK 报的结论是失败; 逐条看 body 里的 devices[].measurement_result\n'
    fi
    if [ "$attest_unknown" -gt 0 ]; then
        printf '              ! 有记录没能从文本里解析出 successful 字段, 看 VERBOSE=1 的原始响应\n'
    fi
fi

if [ "$RECORDS_NEW" -gt 0 ]; then
    printf '服务端记录  : +%s 条 ( %s )\n' "$RECORDS_NEW" "$TIMING_DIR"
    printf '              gpu_script_us = 拿报告那一步, gpu_parse_us = 文本解析;\n'
    printf '              聚合用 python3 tools/summarize_timing.py %s -o log/json/summary.csv\n' "$TIMING_DIR"
else
    printf '服务端记录  : 未发现新增 ( %s )\n' "$TIMING_DIR"
    printf '              若服务端是 release 构建则不会产生耗时 JSON;\n'
    printf '              否则检查 TDX_TIMING_DIR 是否指向了别处。\n'
fi

if [ -n "$OUT_DIR" ]; then
    mkdir -p "$OUT_DIR" || die "无法创建输出目录 $OUT_DIR"
    cp "$CSV" "$OUT_DIR/gpu-timings.csv"
    printf '输出        : %s/gpu-timings.csv\n' "$OUT_DIR"
else
    printf '输出        : 明细未保存 (设 OUT_DIR=目录 可保存 gpu-timings.csv)\n'
fi

# 计时本身只看 HTTP 层是否成功(脚本跑完且输出可解析); 但证明结论是 false 时
# 整个测量通常也没有代表性(比如证书过期导致 SDK 提前失败), 所以那种情况同样非零退出。
[ "$fail" -eq 0 ] || exit 1
[ "$attest_false" -eq 0 ] || exit 1
exit 0
