#!/usr/bin/env python3
"""Fast host-side runner for the Alix HTML/CSS renderer.

Each render runs in a fresh host process.  This gives every job a hard timeout,
turns crashes into ordinary test failures, and allows safe parallel stress even
though ATK/font state is process-global and the UI APIs are single-threaded.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import sys
import time
from typing import Any


RESULT_PREFIX = "WEB_RENDER_RESULT "
DEFAULT_INPUT = "tests/stackoverflow-test/stackoverflow.html"
DEFAULT_BINARY = "build/host-tests/web_render_harness"
DEFAULT_OUTPUT = "test-out/web-render/stackoverflow.png"
DEFAULT_REPORT = "test-out/web-render/report.json"
DEFAULT_IMAGES = 16
DEFAULT_OP_HASH = "0xBA0131C828C32D2E"
DEFAULT_PIXEL_HASH = "0xEB386E6FC697D74D"


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render the captured Stack Overflow page (or another local HTML file) "
            "with Alix's native HTML/CSS/ATK code, without booting Alix."
        )
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help="local HTML input")
    parser.add_argument(
        "--asset-root",
        help="base directory for linked CSS/images (default: input directory)",
    )
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="PNG artifact path")
    parser.add_argument("--report", default=DEFAULT_REPORT, help="JSON report path")
    parser.add_argument("--binary", default=DEFAULT_BINARY, help="native worker binary")

    run_mode = parser.add_mutually_exclusive_group()
    run_mode.add_argument("--repeat", type=positive_int, default=1, help="total isolated runs")
    run_mode.add_argument(
        "--stress",
        nargs="?",
        const=25,
        type=positive_int,
        metavar="RUNS",
        help="stress mode (default 25 runs and up to four parallel workers)",
    )
    parser.add_argument(
        "--parallel",
        type=positive_int,
        help="number of concurrent worker processes (default: 1, or up to 4 for --stress)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=60.0,
        help="hard timeout in seconds for each render (default: 60)",
    )

    parser.add_argument("--layout-only", action="store_true", help="skip pixel draw and PNG")
    parser.add_argument("--no-artifact", action="store_true", help="draw/hash but do not write PNG")
    parser.add_argument(
        "--artifacts-all",
        action="store_true",
        help="write a numbered PNG for every run (normally only run zero writes)",
    )
    parser.add_argument("--no-build", action="store_true", help="do not invoke make first")
    parser.add_argument("--trace", action="store_true", help="enable detailed renderer timing trace")
    parser.add_argument(
        "--dump-dom",
        nargs="?",
        const="",
        metavar="FILTER",
        help="dump computed DOM, optionally filtered by .class or #id",
    )
    parser.add_argument("--expect-op-hash", help="require this render-operation hash")
    parser.add_argument("--expect-pixel-hash", help="require this pixel hash")
    parser.add_argument(
        "--expect-images",
        type=nonnegative_int,
        help="require this many decoded ordinary <img> sources",
    )
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="disable implicit Stack Overflow image/hash goldens for an intentional update",
    )
    parser.add_argument("--verbose", action="store_true", help="print each worker's captured logs")
    parser.add_argument("--json", action="store_true", help="also print the aggregate JSON report")
    return parser


def resolve_from_root(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def normalise_hash(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return f"0x{int(value, 0):016X}"
    except ValueError as error:
        raise ValueError(f"invalid hash {value!r}; expected hexadecimal or integer") from error


def artifact_path(base: Path, index: int, all_artifacts: bool, runs: int) -> Path:
    if not all_artifacts or runs == 1:
        return base
    suffix = base.suffix or ".png"
    return base.with_name(f"{base.stem}-run-{index:04d}{suffix}")


def parse_worker_result(stdout: str) -> dict[str, Any] | None:
    for line in reversed(stdout.splitlines()):
        if line.startswith(RESULT_PREFIX):
            try:
                value = json.loads(line[len(RESULT_PREFIX) :])
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


def clipped_log(value: str | bytes | None, limit: int = 16_384) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if len(value) <= limit:
        return value
    return f"... <{len(value) - limit} bytes omitted> ...\n{value[-limit:]}"


def run_worker(
    *,
    index: int,
    root: Path,
    binary: Path,
    input_path: str,
    asset_root: str | None,
    output_path: Path | None,
    layout_only: bool,
    timeout: float,
    trace: bool,
    dump_dom: str | None,
) -> dict[str, Any]:
    command = [str(binary), "--input", input_path]
    if asset_root:
        command.extend(["--asset-root", asset_root])
    if layout_only:
        command.append("--no-draw")
    elif output_path is not None:
        command.extend(["--output", str(output_path)])
    if dump_dom is not None:
        command.append("--dump-dom" if dump_dom == "" else f"--dump-dom={dump_dom}")

    environment = os.environ.copy()
    if trace:
        environment["ALIX_HTML_TRACE"] = "1"

    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except OSError as error:
        return {
            "index": index,
            "status": "spawn_error",
            "elapsed_ms": (time.monotonic() - started) * 1000.0,
            "command": command,
            "error": str(error),
            "stdout": "",
            "stderr": "",
        }
    except subprocess.TimeoutExpired as error:
        return {
            "index": index,
            "status": "timeout",
            "elapsed_ms": (time.monotonic() - started) * 1000.0,
            "timeout_seconds": timeout,
            "command": command,
            "stdout": clipped_log(error.stdout),
            "stderr": clipped_log(error.stderr),
        }

    elapsed_ms = (time.monotonic() - started) * 1000.0
    result = parse_worker_result(completed.stdout)
    if completed.returncode != 0:
        status = "crash" if completed.returncode < 0 else "failed"
        return {
            "index": index,
            "status": status,
            "elapsed_ms": elapsed_ms,
            "returncode": completed.returncode,
            "command": command,
            "worker_result": result,
            "stdout": clipped_log(completed.stdout),
            "stderr": clipped_log(completed.stderr),
        }
    if not result or result.get("status") != "ok":
        return {
            "index": index,
            "status": "protocol_error",
            "elapsed_ms": elapsed_ms,
            "returncode": completed.returncode,
            "command": command,
            "stdout": clipped_log(completed.stdout),
            "stderr": clipped_log(completed.stderr),
        }

    return {
        "index": index,
        "status": "ok",
        "elapsed_ms": elapsed_ms,
        "returncode": completed.returncode,
        "result": result,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def timing_summary(successes: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    phases = (
        "read",
        "html_parse",
        "css_collect",
        "css_parse",
        "asset_preload",
        "layout",
        "draw",
        "total",
    )
    summary: dict[str, dict[str, float]] = {}
    for phase in phases:
        values = [float(item["result"]["timings_ms"][phase]) for item in successes]
        summary[phase] = {
            "min": min(values),
            "mean": statistics.fmean(values),
            "p50": percentile(values, 0.50),
            "p95": percentile(values, 0.95),
            "max": max(values),
        }
    return summary


def print_worker_logs(items: list[dict[str, Any]]) -> None:
    for item in items:
        stdout = item.get("stdout", "")
        stderr = item.get("stderr", "")
        if stdout:
            print(f"--- worker {item['index']} stdout ---")
            print(stdout, end="" if stdout.endswith("\n") else "\n")
        if stderr:
            print(f"--- worker {item['index']} stderr ---", file=sys.stderr)
            print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]

    runs = args.stress if args.stress is not None else args.repeat
    if args.parallel is not None:
        workers = min(args.parallel, runs)
    elif args.stress is not None:
        workers = min(4, runs, os.cpu_count() or 1)
    else:
        workers = 1

    use_default_baseline = args.input == DEFAULT_INPUT and not args.no_baseline
    expected_images = args.expect_images
    expected_op_value = args.expect_op_hash
    expected_pixel_value = args.expect_pixel_hash
    if use_default_baseline:
        if expected_images is None:
            expected_images = DEFAULT_IMAGES
        if expected_op_value is None:
            expected_op_value = DEFAULT_OP_HASH
        if expected_pixel_value is None and not args.layout_only:
            expected_pixel_value = DEFAULT_PIXEL_HASH

    if args.layout_only and expected_pixel_value:
        parser.error("--expect-pixel-hash cannot be used with --layout-only")
    if args.layout_only and args.artifacts_all:
        parser.error("--artifacts-all cannot be used with --layout-only")
    if args.no_artifact and args.artifacts_all:
        parser.error("--no-artifact and --artifacts-all are mutually exclusive")

    try:
        expected_op_hash = normalise_hash(expected_op_value)
        expected_pixel_hash = normalise_hash(expected_pixel_value)
    except ValueError as error:
        parser.error(str(error))

    binary = resolve_from_root(root, args.binary)
    if not args.no_build:
        build = subprocess.run(["make", "web-render-harness"], cwd=root, check=False)
        if build.returncode != 0:
            print("web_render_harness: native worker build failed", file=sys.stderr)
            return 2
    if not binary.is_file():
        print(f"web_render_harness: worker binary does not exist: {binary}", file=sys.stderr)
        return 2

    output_base = resolve_from_root(root, args.output)
    report_path = resolve_from_root(root, args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if not args.no_artifact and not args.layout_only:
        output_base.parent.mkdir(parents=True, exist_ok=True)

    run_specs: list[tuple[int, Path | None]] = []
    for index in range(runs):
        output_path: Path | None = None
        if not args.no_artifact and not args.layout_only and (index == 0 or args.artifacts_all):
            output_path = artifact_path(output_base, index, args.artifacts_all, runs)
            try:
                output_path.unlink(missing_ok=True)
            except OSError as error:
                print(
                    f"web_render_harness: cannot replace PNG artifact {output_path}: {error}",
                    file=sys.stderr,
                )
                return 2
        run_specs.append((index, output_path))

    wall_start = time.monotonic()
    items: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(
                run_worker,
                index=index,
                root=root,
                binary=binary,
                input_path=args.input,
                asset_root=args.asset_root,
                output_path=output_path,
                layout_only=args.layout_only,
                timeout=args.timeout,
                trace=args.trace,
                dump_dom=args.dump_dom,
            )
            for index, output_path in run_specs
        ]
        for future in concurrent.futures.as_completed(futures):
            items.append(future.result())
    wall_ms = (time.monotonic() - wall_start) * 1000.0
    items.sort(key=lambda item: int(item["index"]))

    successes = [item for item in items if item["status"] == "ok"]
    failures = [item for item in items if item["status"] != "ok"]
    mismatches: list[dict[str, Any]] = []

    baseline_op_hash: str | None = None
    baseline_pixel_hash: str | None = None
    if successes:
        baseline_op_hash = successes[0]["result"].get("op_hash")
        baseline_pixel_hash = successes[0]["result"].get("pixel_hash")
        baseline_counts = successes[0]["result"].get("counts")
        for item in successes:
            result = item["result"]
            if result.get("counts") != baseline_counts:
                mismatches.append(
                    {
                        "index": item["index"],
                        "field": "counts",
                        "expected": baseline_counts,
                        "actual": result.get("counts"),
                    }
                )
            if result.get("op_hash") != baseline_op_hash:
                mismatches.append(
                    {
                        "index": item["index"],
                        "field": "op_hash",
                        "expected": baseline_op_hash,
                        "actual": result.get("op_hash"),
                    }
                )
            if result.get("pixel_hash") != baseline_pixel_hash:
                mismatches.append(
                    {
                        "index": item["index"],
                        "field": "pixel_hash",
                        "expected": baseline_pixel_hash,
                        "actual": result.get("pixel_hash"),
                    }
                )
            if expected_op_hash and result.get("op_hash") != expected_op_hash:
                mismatches.append(
                    {
                        "index": item["index"],
                        "field": "expected_op_hash",
                        "expected": expected_op_hash,
                        "actual": result.get("op_hash"),
                    }
                )
            if expected_pixel_hash and result.get("pixel_hash") != expected_pixel_hash:
                mismatches.append(
                    {
                        "index": item["index"],
                        "field": "expected_pixel_hash",
                        "expected": expected_pixel_hash,
                        "actual": result.get("pixel_hash"),
                    }
                )
            if expected_images is not None and result.get("counts", {}).get("img_loaded") != expected_images:
                mismatches.append(
                    {
                        "index": item["index"],
                        "field": "expected_images",
                        "expected": expected_images,
                        "actual": result.get("counts", {}).get("img_loaded"),
                    }
                )

    passed = len(successes) == runs and not failures and not mismatches
    report: dict[str, Any] = {
        "version": 1,
        "status": "pass" if passed else "fail",
        "input": args.input,
        "asset_root": args.asset_root,
        "mode": "layout" if args.layout_only else "render",
        "runs": runs,
        "parallel_workers": workers,
        "timeout_seconds": args.timeout,
        "expected": {
            "images": expected_images,
            "op_hash": expected_op_hash,
            "pixel_hash": expected_pixel_hash,
            "implicit_stackoverflow_baseline": use_default_baseline,
        },
        "wall_ms": wall_ms,
        "throughput_runs_per_second": runs / (wall_ms / 1000.0) if wall_ms > 0 else 0.0,
        "baseline": successes[0]["result"] if successes else None,
        "timings_ms": timing_summary(successes) if successes else {},
        "failures": failures,
        "hash_mismatches": mismatches,
        "runs_detail": [
            {
                key: value
                for key, value in item.items()
                if key not in {"stdout", "stderr", "command"}
            }
            for item in items
        ],
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.verbose or failures:
        print_worker_logs(items if args.verbose else failures)

    label = "PASS" if passed else "FAIL"
    print(
        f"web_render_harness: {label} runs={runs} passed={len(successes)} "
        f"workers={workers} wall={wall_ms:.1f}ms"
    )
    if successes:
        baseline = successes[0]["result"]
        counts = baseline["counts"]
        print(
            "web_render_harness: "
            f"op_hash={baseline_op_hash} pixel_hash={baseline_pixel_hash} "
            f"nodes={counts['nodes']} rules={counts['rules']} ops={counts['ops']} "
            f"images={counts['images']} img_loaded={counts['img_loaded']} "
            f"css_images={counts['css_images_loaded']} assets_failed={counts['assets_failed']} "
            f"remote_skipped={counts['assets_remote_skipped']}"
        )
        timing = report["timings_ms"]
        print(
            "web_render_harness: timings "
            f"assets p50={timing['asset_preload']['p50']:.1f}ms p95={timing['asset_preload']['p95']:.1f}ms; "
            f"layout p50={timing['layout']['p50']:.1f}ms p95={timing['layout']['p95']:.1f}ms; "
            f"draw p50={timing['draw']['p50']:.1f}ms p95={timing['draw']['p95']:.1f}ms; "
            f"total p50={timing['total']['p50']:.1f}ms p95={timing['total']['p95']:.1f}ms"
        )
    if failures:
        for failure in failures:
            detail = failure.get("returncode", failure.get("timeout_seconds", "unknown"))
            print(
                f"web_render_harness: run {failure['index']} {failure['status']} ({detail})",
                file=sys.stderr,
            )
    if mismatches:
        for mismatch in mismatches:
            print(
                "web_render_harness: nondeterministic/incorrect "
                f"{mismatch['field']} on run {mismatch['index']}: "
                f"expected {mismatch['expected']}, got {mismatch['actual']}",
                file=sys.stderr,
            )
    if not args.no_artifact and not args.layout_only:
        if args.artifacts_all and runs > 1:
            print(
                "web_render_harness: PNGs "
                f"{artifact_path(output_base, 0, True, runs)} .. "
                f"{artifact_path(output_base, runs - 1, True, runs)}"
            )
        else:
            print(f"web_render_harness: PNG {output_base}")
    print(f"web_render_harness: report {report_path}")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
