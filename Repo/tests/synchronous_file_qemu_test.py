#!/usr/bin/env python3
"""Verify concurrent native O_SYNC writes and independent AlixFS remount readback."""
import hashlib
import json
from pathlib import Path
import tempfile
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    output = ROOT / "build/test-out"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="alix-synchronous-file-") as directory:
        blank = Path(directory) / "blank.img"
        snapshot = output / "synchronous-file-committed.img"
        with blank.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024)
        run_native_elf("synchronous_file_test.elf",
            ("SYNCHRONOUS_FILE_TEST: PASS cpus=8 writes=64 bytes=32768 append=1 aliases=1 immutable=1 checked_copy=1 nonblock_open=1",),
            output / "synchronous-file-qemu.log", "Native synchronous file writes", 90,
            expected_wait_status=0, fail_on_missing_markers_at_exit=True,
            disk_fixture=blank, disk_snapshot=snapshot,
            setup_commands=(("mkfs /dev/ahci1", "mkfs complete"),
                            ("mount /dev/ahci1 /tmp/sync-disk", "mount complete")))
        with snapshot.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        run_native_elf("synchronous_file_test.elf",
            ("SYNCHRONOUS_FILE_REMOUNT_TEST: PASS bytes=32768 records=64 explicit_fsync=0",),
            output / "synchronous-file-remount-qemu.log", "Synchronous writes independent remount", 45,
            arguments=("read",), disk_fixture=snapshot, expected_wait_status=0,
            fail_on_missing_markers_at_exit=True)
        (output / "synchronous-file-remount.acceptance.json").write_text(json.dumps({
            "scope": "Native O_SYNC writes and independent remount; full NSPR and Zen remain unverified",
            "cpus": 8, "writes": 64, "bytes": 32768, "explicit_fsync": False,
            "guest_shutdown_before_snapshot": False, "physical_power_loss_tested": False,
            "disk_bytes": snapshot.stat().st_size, "disk_sha256": digest,
        }, indent=2) + "\n")
    run_native_elf("synchronous_file_legacy_test.elf",
        ("SYNCHRONOUS_FILE_LEGACY_TEST: PASS unsupported=1 truncate_preserved=1 raw_kernel=1",),
        output / "synchronous-file-legacy-qemu.log", "Legacy synchronous open rejection", 30,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
