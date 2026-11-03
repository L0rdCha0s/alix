#!/usr/bin/env python3
"""Verify actual old/new stat entry points and stable VFS identities in Alix."""
from cpp_runtime_qemu_test import ROOT, run_native_elf
from pathlib import Path
import tempfile
import json
import hashlib

if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="alix-identity-") as temporary:
        blank = Path(temporary) / "blank.img"
        snapshot = Path(temporary) / "persisted.img"
        with blank.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024)
        run_native_elf("file_identity_test.elf", (
            "FILE_IDENTITY_TEST: PASS cpus=8 snapshots=512 versions=2 canaries=1 independent_opens=1 aliases=1 readdir=1 rename=1 orphan=1 recreate=1 directories=1 copy_checks=1 ownership=1 mount_identity=1 modes=1 times=1",
        ), ROOT / "build/test-out/file-identity-qemu.log", "Native versioned file identity", 120,
            expected_wait_status=0, fail_on_missing_markers_at_exit=True,
            disk_fixture=blank, disk_snapshot=snapshot,
            setup_commands=(("mkfs /dev/ahci1", "mkfs complete"), ("mount /dev/ahci1 /tmp/identity-disk", "mount complete")))
        run_native_elf("file_identity_test.elf", ("FILE_IDENTITY_REMOUNT: PASS owner=12345 group=23456 bytes=8 mode=0640 times=1",),
            ROOT / "build/test-out/file-identity-remount-qemu.log", "File ownership independent remount", 60,
            arguments=("read",), disk_fixture=snapshot, expected_wait_status=0, fail_on_missing_markers_at_exit=True)
        output = ROOT / "build/test-out"
        boots = [json.loads((output / name).read_text()) for name in
                 ("file-identity-qemu.boot-image.json", "file-identity-remount-qemu.boot-image.json")]
        if boots[0] != boots[1]:
            raise RuntimeError("file identity boots did not use the same kernel/loader/user images")
        (output / "file-identity.acceptance.json").write_text(json.dumps({
            "scope": "Versioned stat, file ownership and basic modes; byte locks and full browser remain separate",
            "cpus": 8, "snapshots": 512, "stat_record_bytes": [40, 88],
            "legacy_canaries": True, "stable_readdir_rename_identity": True,
            "unlinked_open_file": True, "independent_owner_readback": [12345, 23456], "persisted_mode": "0640",
            "persisted_times_seconds": [1600000000,1600000001],
            "boot": boots[0], "committed_disk_sha256": hashlib.sha256(snapshot.read_bytes()).hexdigest(),
        }, indent=2) + "\n")
