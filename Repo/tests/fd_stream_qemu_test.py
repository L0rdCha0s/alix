#!/usr/bin/env python3
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("fd_stream_test.elf",
        ("FD_STREAM_TEST: PASS aliases=1 nonblock=1 pipe_atomic=1 fdopen=1 append=1 offset64=1",),
        ROOT / "build/test-out/fd-stream-native-qemu.log", "native descriptor streams", 55,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
