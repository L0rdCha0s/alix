#!/usr/bin/env python3
"""Execute the native Clang/C++ runtime and application abort-hook profile."""
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]


def main():
    subprocess.run(["make", "all", "zen-toolchain-test"], cwd=ROOT, check=True)
    for arguments, markers, forbidden, filename in (
        ((), ("ALIX_TOOLCHAIN_STDIO: line", "ALIX_TOOLCHAIN_TEST: PASS"),
         ("ALIX_TOOLCHAIN_TEST: FAIL", "ALIX_ABORT_OVERRIDE"), "alix-toolchain-qemu.log"),
        (("abort",), ("ALIX_ABORT_OVERRIDE: PASS",),
         ("ALIX_TOOLCHAIN_TEST:", "ALIX_TOOLCHAIN_STDIO:"), "alix-abort-override-qemu.log"),
    ):
        log = ROOT / "build/test-out" / filename
        run_native_elf("alix_toolchain_test.elf", markers, log, "Native C++ compiler/math/abort profile",
                       timeout_seconds=90, arguments=arguments, forbidden_markers=forbidden)
        if log.read_text(errors="replace").count(markers[0]) != 1:
            raise RuntimeError("native compiler fixture output was duplicated")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Native toolchain acceptance failed: {error}", file=sys.stderr)
        sys.exit(1)
