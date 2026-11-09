#!/usr/bin/env python3
"""对 debug 构建产生的逐请求耗时 JSON 做统计，输出一个 CSV。

输入是 src/metrics.rs 写出的文件（默认 <项目>/log/json/*.json），每条记录长这样::

    {
      "ts": "2026-11-06T07:04:51Z", "route": "/attestation_all",
      "http_status": 200, "warm": true, "concurrency": 1,
      "e2e_server_us": 128400, "e2e_client_us": null,
      "stages": { "create_quote_us": 62400, ... },
      "units":  { "tpm2_quote_us": 25600, "files_measured": 6 },
      "unattributed_us": -1288, "checksum_ok": true
    }

输出的 CSV 是**长表**（每个 route 的每个指标一行），列含义::

    kind         e2e / stage / unit / counter / derived
    metric       指标名，如 create_quote_us
    unit         us=微秒；count=计数（files_measured 之类，不是耗时）
    n            有多少条记录带这个指标（各指标可能不同）
    mean/std     均值与样本标准差（ddof=1）
    cv           变异系数 std/mean，看抖动大不大
    min/p50/p90/p99/max                  分位数用最近秩法
    share_pct    该指标均值占 e2e 均值的百分比（计数器留空）

用法::

    python3 tools/summarize_timing.py                     # 读 <项目>/log/json
    python3 tools/summarize_timing.py log/json -o out.csv
    python3 tools/summarize_timing.py log/json --group-by route,warm
    python3 tools/summarize_timing.py log/json --since 2026-11-06T08:00:00Z
    python3 tools/summarize_timing.py log/json --raw raw.csv   # 额外导出逐请求宽表

默认只统计 http_status=200 且 checksum_ok=true 的记录；被排除的条数会打印出来，
想全都算上就加 --keep-failed / --keep-inconsistent。
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

DURATION_SUFFIX = "_us"
DEFAULT_GROUP_BY = "route"

KIND_ORDER = {"e2e": 0, "stage": 1, "unit": 2, "counter": 3, "derived": 4}

CSV_HEADER = [
    "kind",
    "metric",
    "unit",
    "n",
    "mean",
    "std",
    "cv",
    "min",
    "p50",
    "p90",
    "p99",
    "max",
    "share_pct",
]


# ---------------------------------------------------------------------------
# 统计基础
# ---------------------------------------------------------------------------


def percentile(sorted_values: Sequence[float], p: float) -> float:
    """最近秩法（nearest-rank）：第 ceil(p*n) 个，1-based。

    和小样本下 `numpy.percentile(..., method="nearest")` 一致；不做插值，
    因为指标本身就是整数微秒，插值出来的小数没有物理意义。
    """
    n = len(sorted_values)
    if n == 0:
        return 0.0
    idx = math.ceil(p * n)
    idx = min(max(idx, 1), n)
    return sorted_values[idx - 1]


def describe(values: Sequence[float]) -> Dict[str, float]:
    """n / mean / std(ddof=1) / cv / min / 分位数 / max。"""
    n = len(values)
    if n == 0:
        return {k: 0.0 for k in ("n", "mean", "std", "cv", "min", "p50", "p90", "p99", "max")}

    ordered = sorted(values)
    mean = sum(ordered) / n
    if n > 1:
        var = sum((v - mean) ** 2 for v in ordered) / (n - 1)
        std = math.sqrt(var)
    else:
        std = 0.0

    return {
        "n": float(n),
        "mean": mean,
        "std": std,
        "cv": (std / mean) if mean else 0.0,
        "min": ordered[0],
        "p50": percentile(ordered, 0.50),
        "p90": percentile(ordered, 0.90),
        "p99": percentile(ordered, 0.99),
        "max": ordered[-1],
    }


def is_duration(name: str) -> bool:
    """`*_us` 是耗时，其余（files_measured 之类）是计数。"""
    return name.endswith(DURATION_SUFFIX)


# ---------------------------------------------------------------------------
# 读取
# ---------------------------------------------------------------------------


def collect_files(root: Path, recursive: bool) -> List[Path]:
    pattern = "**/*.json" if recursive else "*.json"
    return sorted(p for p in root.glob(pattern) if p.is_file())


def load(records: List[Path]) -> Tuple[List[Tuple[Path, Dict[str, Any]]], int]:
    """读取所有 JSON；坏文件跳过并计数。"""
    loaded: List[Tuple[Path, Dict[str, Any]]] = []
    broken = 0
    for path in records:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            broken += 1
            continue
        if not isinstance(data, dict):
            broken += 1
            continue
        loaded.append((path, data))
    return loaded, broken


# ---------------------------------------------------------------------------
# 聚合
# ---------------------------------------------------------------------------


class Group:
    """一个 group（默认一个 route）的样本容器。"""

    __slots__ = ("e2e", "metrics", "sum_stages", "unattributed", "records")

    def __init__(self) -> None:
        self.e2e: List[float] = []
        self.metrics: Dict[Tuple[str, str], List[float]] = {}
        self.sum_stages: List[float] = []
        self.unattributed: List[float] = []
        self.records = 0

    def add_metric(self, kind: str, name: str, value: float) -> None:
        self.metrics.setdefault((kind, name), []).append(value)


def numbers(mapping: Any) -> Iterable[Tuple[str, float]]:
    if not isinstance(mapping, dict):
        return
    for name, value in mapping.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        yield str(name), float(value)


def group_key(record: Dict[str, Any], fields: Sequence[str]) -> Tuple[str, ...]:
    return tuple(str(record.get(field, "")) for field in fields)


def aggregate(
    loaded: List[Tuple[Path, Dict[str, Any]]],
    group_fields: Sequence[str],
    keep_failed: bool,
    keep_inconsistent: bool,
    since: Optional[str],
) -> Tuple[Dict[Tuple[str, ...], Group], Dict[str, int]]:
    groups: Dict[Tuple[str, ...], Group] = {}
    skipped = {"failed": 0, "inconsistent": 0, "no_e2e": 0, "before_since": 0}

    for _path, record in loaded:
        ts = str(record.get("ts", ""))
        if since and ts and ts < since:
            skipped["before_since"] += 1
            continue

        status = record.get("http_status")
        if not keep_failed and status != 200:
            skipped["failed"] += 1
            continue

        if not keep_inconsistent and record.get("checksum_ok") is False:
            skipped["inconsistent"] += 1
            continue

        e2e = record.get("e2e_server_us")
        if not isinstance(e2e, (int, float)) or isinstance(e2e, bool):
            skipped["no_e2e"] += 1
            continue
        e2e = float(e2e)

        key = group_key(record, group_fields)
        group = groups.get(key)
        if group is None:
            group = groups[key] = Group()

        group.records += 1
        group.e2e.append(e2e)

        stage_total = 0.0
        for name, value in numbers(record.get("stages")):
            group.add_metric("stage", name, value)
            stage_total += value
        group.sum_stages.append(stage_total)

        unattributed = record.get("unattributed_us")
        if isinstance(unattributed, (int, float)) and not isinstance(unattributed, bool):
            group.unattributed.append(float(unattributed))

        for name, value in numbers(record.get("units")):
            kind = "unit" if is_duration(name) else "counter"
            group.add_metric(kind, name, value)

    return groups, skipped


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------


def fmt(value: float, unit: str) -> str:
    """耗时保留两位小数；计数尽量写成整数。"""
    if unit == "count":
        if float(value).is_integer():
            return str(int(value))
        return f"{value:.2f}"
    return f"{value:.2f}"


def build_rows(
    groups: Dict[Tuple[str, ...], Group],
    group_fields: Sequence[str],
    include_derived: bool = True,
) -> List[List[str]]:
    rows: List[List[str]] = []

    for key, group in groups.items():
        e2e = describe(group.e2e)
        e2e_mean = e2e["mean"]

        def emit(kind: str, metric: str, unit: str, values: Sequence[float]) -> None:
            stats = describe(values)
            share = ""
            if unit == "us" and e2e_mean:
                share = f"{stats['mean'] / e2e_mean * 100:.2f}"
            rows.append(
                list(key)
                + [
                    kind,
                    metric,
                    unit,
                    str(int(stats["n"])),
                    fmt(stats["mean"], unit),
                    fmt(stats["std"], unit),
                    f"{stats['cv']:.4f}",
                    fmt(stats["min"], unit),
                    fmt(stats["p50"], unit),
                    fmt(stats["p90"], unit),
                    fmt(stats["p99"], unit),
                    fmt(stats["max"], unit),
                    share,
                ]
            )

        emit("e2e", "e2e_server_us", "us", group.e2e)
        for (kind, name), values in group.metrics.items():
            emit(kind, name, "us" if is_duration(name) else "count", values)

        if include_derived:
            emit("derived", "sum_stages", "us", group.sum_stages)
            if group.unattributed:
                emit("derived", "unattributed", "us", group.unattributed)

    kind_rank = {kind: rank for kind, rank in KIND_ORDER.items()}

    def sort_key(row: List[str]) -> Tuple[Any, ...]:
        # 先按分组把每个 route 聚成连续一块，再按 kind、再按均值从大到小。
        # 单 route 时输出与"kind 优先"完全一致；多 route 时读起来清楚得多。
        group = tuple(row[: len(group_fields)])
        kind = row[len(group_fields)]
        metric = row[len(group_fields) + 1]
        try:
            mean = float(row[len(group_fields) + 4])
        except ValueError:
            mean = 0.0
        return (group, kind_rank.get(kind, 9), -mean, metric)

    rows.sort(key=sort_key)
    return rows


def write_stats(path: Path, group_fields: Sequence[str], rows: List[List[str]]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(list(group_fields) + CSV_HEADER)
        writer.writerows(rows)


def write_raw(path: Path, loaded: List[Tuple[Path, Dict[str, Any]]]) -> int:
    """逐请求宽表，便于自己画趋势图或做别的统计。"""
    columns: List[str] = []
    seen = set()
    prepared: List[Dict[str, Any]] = []

    for source, record in loaded:
        flat: Dict[str, Any] = {
            "file": source.name,
            "ts": record.get("ts", ""),
            "route": record.get("route", ""),
            "http_status": record.get("http_status", ""),
            "warm": record.get("warm", ""),
            "concurrency": record.get("concurrency", ""),
            "e2e_server_us": record.get("e2e_server_us", ""),
            "unattributed_us": record.get("unattributed_us", ""),
            "checksum_ok": record.get("checksum_ok", ""),
        }
        for bucket in ("stages", "units"):
            for name, value in numbers(record.get(bucket)):
                flat[name] = value
        for name in flat:
            if name not in seen:
                seen.add(name)
                columns.append(name)
        prepared.append(flat)

    head = ["file", "ts", "route", "http_status", "warm", "concurrency",
            "e2e_server_us", "unattributed_us", "checksum_ok"]
    extra = sorted(name for name in columns if name not in head)
    header = head + extra

    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        for row in prepared:
            writer.writerow(row)
    return len(prepared)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def default_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "log" / "json"


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="统计 log/json/*.json 的耗时并输出 CSV",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("directory", nargs="?", default=None, help="JSON 所在目录（默认 <项目>/log/json）")
    parser.add_argument("-o", "--output", default=None, help="输出 CSV（默认 <目录>/summary.csv）")
    parser.add_argument("--group-by", default=DEFAULT_GROUP_BY,
                        help="分组字段，逗号分隔，可用 route,warm,concurrency,http_status")
    parser.add_argument("--since", default=None,
                        help="只看这个时间之后的记录（ISO 字符串比较，如 2026-11-06T08:00:00Z）")
    parser.add_argument("--recursive", action="store_true", help="递归子目录")
    parser.add_argument("--keep-failed", action="store_true", help="保留 http_status != 200 的记录")
    parser.add_argument("--keep-inconsistent", action="store_true", help="保留 checksum_ok=false 的记录")
    parser.add_argument("--raw", default=None, help="额外导出逐请求宽表 CSV")
    parser.add_argument("-q", "--quiet", action="store_true", help="不打印文字摘要")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)

    root = Path(args.directory) if args.directory else default_dir()
    if not root.is_dir():
        print(f"error: 目录不存在: {root}", file=sys.stderr)
        return 2

    files = collect_files(root, args.recursive)
    if not files:
        print(f"error: {root} 下没有 *.json", file=sys.stderr)
        print("       服务端是 release 构建时不会产生耗时记录；", file=sys.stderr)
        print("       或用 TDX_TIMING_DIR 指定了别的目录。", file=sys.stderr)
        return 2

    group_fields = [f.strip() for f in args.group_by.split(",") if f.strip()]
    if not group_fields:
        print("error: --group-by 不能为空", file=sys.stderr)
        return 2

    loaded, broken = load(files)
    if not loaded:
        print(f"error: {len(files)} 个文件都读不出来", file=sys.stderr)
        return 2

    groups, skipped = aggregate(
        loaded, group_fields, args.keep_failed, args.keep_inconsistent, args.since
    )

    output = Path(args.output) if args.output else root / "summary.csv"
    output.parent.mkdir(parents=True, exist_ok=True)

    rows = build_rows(groups, group_fields)
    write_stats(output, group_fields, rows)

    raw_rows = None
    if args.raw:
        raw_path = Path(args.raw)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_rows = write_raw(raw_path, loaded)

    if not args.quiet:
        total = sum(g.records for g in groups.values())
        print(f"扫描目录 : {root}")
        print(f"文件数   : {len(files)} (读取失败 {broken})")
        print(f"有效记录 : {total}")
        if skipped["failed"]:
            print(f"  排除   : http_status != 200 -> {skipped['failed']} 条 (--keep-failed 可保留)")
        if skipped["inconsistent"]:
            print(f"  排除   : checksum_ok=false  -> {skipped['inconsistent']} 条 (--keep-inconsistent 可保留)")
        if skipped["before_since"]:
            print(f"  排除   : 早于 --since      -> {skipped['before_since']} 条")
        if skipped["no_e2e"]:
            print(f"  排除   : 缺 e2e_server_us  -> {skipped['no_e2e']} 条")

        for key, group in sorted(groups.items()):
            e2e = describe(group.e2e)
            label = "/".join(f"{f}={v}" for f, v in zip(group_fields, key))
            print(f"\n[{label}] n={int(e2e['n'])}  "
                  f"e2e mean={e2e['mean']:.1f} us  std={e2e['std']:.1f}  "
                  f"p50={e2e['p50']:.1f}  p99={e2e['p99']:.1f}  max={e2e['max']:.1f}")
            # 只列耗时项，按均值占比从大到小；计数项没有占比，单独一句话带过。
            durations = []
            for (kind, name), values in group.metrics.items():
                if kind == "counter":
                    continue
                stats = describe(values)
                durations.append((stats["mean"], kind, name, stats))
            durations.sort(reverse=True)
            for mean, kind, name, stats in durations:
                share = mean / e2e["mean"] * 100 if e2e["mean"] else 0.0
                print(f"    {kind:<6} {name:<24} mean={mean:>11.1f}  "
                      f"std={stats['std']:>10.1f}  p99={stats['p99']:>11.1f}  {share:5.1f}%")
            counters = [name for (kind, name) in group.metrics if kind == "counter"]
            if counters:
                detail = ", ".join(
                    f"{name}={describe(group.metrics[('counter', name)])['mean']:.1f}"
                    for name in counters
                )
                print(f"    counters {detail}")

            # 阶段和不该超过总时长：超了说明样本本身不自洽（见字段文档第 5 节）。
            if group.sum_stages and e2e["mean"]:
                stage_mean = describe(group.sum_stages)["mean"]
                if stage_mean > e2e["mean"] * 1.05:
                    print(
                        f"    ! 警告: Σstages 均值 {stage_mean:.0f} us 超过 e2e 均值 "
                        f"{e2e['mean']:.0f} us, 记录可能不自洽 "
                        f"(docs/attestation-sample-record-fields.md 第 5 节)"
                    )

        print(f"\nCSV      : {output} ({len(rows)} 行)")
        if raw_rows is not None:
            print(f"逐请求表 : {args.raw} ({raw_rows} 行)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
