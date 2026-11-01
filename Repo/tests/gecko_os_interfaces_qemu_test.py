#!/usr/bin/env python3
"""Verify native OS interfaces and fsync readback on a disposable AlixFS disk."""
import hashlib
import json
from pathlib import Path
import tempfile

from cpp_runtime_qemu_test import ROOT, run_native_elf


def main():
    output = ROOT / "build/test-out"
    output.mkdir(parents=True, exist_ok=True)
    # Each harness boot copies this input; the user's data.img is never used.
    with tempfile.TemporaryDirectory(prefix="alix-fsync-test-") as directory:
        directory = Path(directory)
        blank, snapshot = directory / "blank.img", output / "fsync-resized-committed.img"
        with blank.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024)
        run_native_elf("gecko_os_interfaces_test.elf",
            ("GECKO_OS_INTERFACES_TEST: PASS cpus=8 fsync=1 madv_willneed=1 memory_pages=1",),
            output / "gecko-os-interfaces-qemu.log", "native Gecko OS interfaces", 90,
            expected_wait_status=0, fail_on_missing_markers_at_exit=True,
            disk_fixture=blank, disk_snapshot=snapshot,
            setup_commands=(("mkfs /dev/ahci1", "mkfs complete"),
                            ("mount /dev/ahci1 /tmp/fsync-disk", "mount complete")))
        with snapshot.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        run_native_elf("gecko_os_interfaces_test.elf",
            ("FSYNC_REMOUNT_TEST: PASS bytes=65536 metadata=1",
             "FILE_RESIZE_REMOUNT_TEST: PASS bytes=8192 shrink=1 grow=1 zero_fill=1"),
            output / "fsync-remount-qemu.log", "fsync independent remount", 60,
            arguments=("read",), disk_fixture=snapshot,
            expected_wait_status=0, fail_on_missing_markers_at_exit=True)
        receipt = {
            "cpus": 8, "fsync_concurrent_callers": 8, "payload_bytes": 65536,
            "disk_bytes": snapshot.stat().st_size, "disk_sha256": digest,
            "independent_remount": True, "guest_shutdown_before_snapshot": False,
            "physical_power_loss_tested": False,
            "resized_file_bytes": 8192, "resize_shrink_grow_zero_fill_remount": True,
            "madv_willneed": "validated non-destructive optional hint",
            "physical_page_queries": "native PMM, total and currently available",
        }
        (output / "gecko-os-interfaces.acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
