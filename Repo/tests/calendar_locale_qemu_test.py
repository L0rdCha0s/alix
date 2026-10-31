#!/usr/bin/env python3
"""Verify native calendar/locale, wall time and timezone snapshot APIs."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    try:
        sys.exit(run_native_elf("calendar_locale_test.elf",
            ("CALENDAR_LOCALE_TEST: PASS workers=8 cpu_mask=0xFF utc=1 locale=1 wall=1 snapshot=1",),
            ROOT / "build/test-out/calendar-locale-qemu.log",
            "Native calendar, locale and timezone snapshot", 60))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Calendar/locale QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
