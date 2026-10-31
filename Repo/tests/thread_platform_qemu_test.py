#!/usr/bin/env python3
"""Exercise native TLS and blocking synchronization in isolated Alix guests."""
import argparse
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test", choices=("tls", "elf_tls", "pool", "libc", "main_exit", "pthread", "pthread_initial", "sync", "memory", "all"), default="all")
    args = parser.parse_args()
    tests = {
        "tls": ("thread_tls_test.elf", "THREAD_TLS_TEST: PASS", "Native thread-local storage"),
        "elf_tls": ("thread_elf_tls_test.elf", "ELF_TLS_TEST: PASS", "Compiler-generated ELF TLS"),
        "pool": ("thread_pool_reuse_test.elf", "THREAD_POOL_REUSE_TEST: PASS", "Thread stack and TLS address reuse"),
        "libc": ("thread_libc_support_test.elf", "LIBC_SUPPORT_TEST: main PASS", "C runtime lifecycle and allocation"),
        "main_exit": ("thread_main_exit_test.elf", "MAIN_THREAD_EXIT_TEST: PASS", "Initial thread exit and last-thread finalization"),
        "pthread": ("thread_pthread_test.elf", "THREAD_PTHREAD_TEST: main PASS", "POSIX thread ABI and lifetimes"),
        "pthread_initial": ("thread_pthread_test.elf", "THREAD_PTHREAD_TEST: initial-exit PASS", "POSIX initial-thread exit"),
        "sync": ("thread_sync_test.elf", "THREAD_SYNC_TEST: PASS", "Native blocking synchronization"),
        "memory": ("thread_memory_test.elf", "MEMORY_PLATFORM_TEST: PASS", "Native heap shrink and reclamation"),
    }
    for name, (binary, marker, label) in tests.items():
        if args.test in (name, "all"):
            markers = (marker, "LIBC_SUPPORT_TEST: exit PASS") if name == "libc" else (marker,)
            if name == "pthread": markers = (marker, "THREAD_PTHREAD_TEST: exit PASS")
            run_native_elf(binary, markers, ROOT / f"build/test-out/thread-{name}-qemu.log",
                           label, timeout_seconds=120 if name == "pool" else 60,
                           arguments=("initial-exit",) if name == "pthread_initial" else ())
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Thread platform QEMU test failed: {error}", file=sys.stderr)
        sys.exit(1)
