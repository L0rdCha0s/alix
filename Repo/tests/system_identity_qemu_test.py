#!/usr/bin/env python3
"""Correlate native uname with the actual kernel ELF and concurrent hostname I/O."""
import hashlib
import json
import re
import subprocess
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    kernel = ROOT / "build/alix.elf"
    digest = hashlib.sha256(kernel.read_bytes()).hexdigest()
    notes = subprocess.check_output(["x86_64-elf-readelf", "-n", str(kernel)], text=True)
    build_id = re.search(r"Build ID: ([0-9a-f]{40})", notes).group(1)
    log = ROOT / "build/test-out/system-identity-qemu.log"
    run_native_elf("system_identity_test.elf",
        (f"version=build:{build_id}",
         "SYSTEM_IDENTITY_TEST: PASS cpus=8 snapshots=512 replacements=64 hostname=1 credentials=1 checked_copy=1 bounds=1 build_id=1"),
        log, "Native system identity", 90, expected_wait_status=0,
        fail_on_missing_markers_at_exit=True)
    boot = json.loads(log.with_suffix(".boot-image.json").read_text())
    if boot["kernel_sha256"] != digest:
        raise RuntimeError("uname build identity was tested with a different kernel image")
    log.with_suffix(".acceptance.json").write_text(json.dumps({
        "scope": "Native system identity; complete NSPR and Zen are not verified",
        "kernel_build_id": build_id, "kernel_sha256": digest, "boot": boot,
    }, indent=2) + "\n")
