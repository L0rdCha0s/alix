#!/usr/bin/env python3
"""Verify distinct normal/signal wait encodings recorded by native processes."""
from pathlib import Path
import re
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(["make", "all", "build/user/process_wait_status_test.elf"], cwd=ROOT, check=True)
    cases = {"normal": 141 << 8, "raise": 13, "kill": 15, "fault": 4}
    modes = sys.argv[1:] or list(cases)
    for mode in modes:
        if mode not in cases:
            raise RuntimeError(f"unknown termination mode: {mode}")
        expected = cases[mode]
        log = ROOT / f"build/test-out/wait-status-{mode}-qemu.log"
        options = {}
        if mode == "raise":
            options["expected_signal_termination"] = ("WAIT_STATUS_TEST: armed", "raise", 13, 141, 0, None)
        elif mode == "fault":
            options["expected_signal_termination"] = ("WAIT_STATUS_TEST: armed", "fault", 4, 132, 6, "wait_status_ud2")
            options["expected_exception"] = ("invalid_opcode", "wait_status_ud2")
        marker = "WAIT_STATUS_TEST: normal armed" if mode == "normal" else "WAIT_STATUS_TEST: armed"
        run_native_elf("process_wait_status_test.elf", (marker,), log,
                       f"Native wait status {mode}", timeout_seconds=90, arguments=(mode,),
                       forbidden_markers=("WAIT_STATUS_TEST: FAIL",), **options)
        text = log.read_text(errors="replace")
        armed = re.search(re.escape(marker) + r" pid=(\d+) tid=\d+", text)
        records = re.findall(r"\[proc\] destroy pid=0x([0-9A-Fa-f]+) name=/tmp/test\.elf "
                             r"main_thread=0x[0-9A-Fa-f]+ wait_status=(\d+)", text)
        matching = [int(status) for pid, status in records if armed and int(pid, 16) == int(armed.group(1))]
        if matching != [expected]:
            raise RuntimeError(f"{mode} did not retain its exact termination cause: {matching!r}")
    print("Native termination encoding PASS: " + ", ".join(modes))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Wait status acceptance failed: {error}", file=sys.stderr)
        sys.exit(1)
