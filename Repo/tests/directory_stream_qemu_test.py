#!/usr/bin/env python3
"""Verify native directory streams and shared cursor concurrency inside Alix."""
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]
run_native_elf('directory_stream_test.elf',
               ('DIRECTORY_STREAM_TEST: PASS workers=8 mask=0xFF exact_once=50 names180=1 UTF8=1 snapshot=1 limit256=1',),
               ROOT / 'build/test-out/directory-stream-qemu.log',
               'Native directory streams on eight CPUs', timeout_seconds=120,
               forbidden_markers=('DIRECTORY_STREAM_TEST: FAIL',))
print('Native directory stream acceptance PASS')
