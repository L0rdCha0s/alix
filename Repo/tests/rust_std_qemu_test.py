#!/usr/bin/env python3
"""Execute the upstream Rust standard library against native Alix services."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    try:
        sys.exit(run_native_elf("rust_std_test.elf",
            ("RUST_THREAD_HANDLES_TEST: PASS workers=8 native_ids=1 names=1 stack=1 raw_join=16 raw_detach=16 drop_detach=16 tls_dtors=56",
             "RUST_FILESYSTEM_TEST: PASS cpus=8 owned_fd=1 clone_offset=1 cloexec=1 resize=1 metadata=1 paths=1 dirs=1 exclusive=1 bytes=1 pipes=1",
             "RUST_ENVIRONMENT_TEST: PASS cpus=8 updates=1536 snapshots=512 bytes=1 owned=1 cwd=1 exe=1 paths=1 home=1 accounts=1",
             "RUST_FILE_LOCKS_TEST: PASS cpus=8 sections=256 shared=1 aliases=1 close=1 wait=1 would_block=1 unsupported=1",
             "RUST_STD_TEST: PASS"),
            ROOT / "build/test-out/rust-std-qemu.log", "Upstream Rust std", 90,
            tcg_cpu="qemu64,+rdrand", expected_wait_status=0, fail_on_missing_markers_at_exit=True))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Rust standard-library QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
