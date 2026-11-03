#!/usr/bin/env python3
"""Exercise native named memory and verify its namespace does not persist."""
from pathlib import Path
import hashlib
import json
import tempfile
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="alix-shm-") as temporary:
        blank = Path(temporary) / "blank.img"
        snapshot = Path(temporary) / "persisted.img"
        with blank.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024)
        run_native_elf("shared_memory_test.elf", (
            "SHM_TEST: PASS cpus=8 shared=512 exclusive=1 readonly=1 unlink=1 replace=1 cloexec=1 spawn=1 killed_creator=1 fd_limit=1",
        ), ROOT / "build/test-out/shared-memory-qemu.log", "Native named shared memory", 180,
            expected_wait_status=0, fail_on_missing_markers_at_exit=True,
            disk_fixture=blank, disk_snapshot=snapshot,
            setup_commands=(("mkfs /dev/ahci1", "mkfs complete"), ("mount /dev/ahci1 /tmp/shm-disk", "mount complete")))
        run_native_elf("shared_memory_test.elf", ("SHM_REBOOT_TEST: PASS namespace_reset=1 disk_marker=1",),
            ROOT / "build/test-out/shared-memory-reboot-qemu.log", "Shared-memory namespace independent reboot", 90,
            expected_wait_status=0, fail_on_missing_markers_at_exit=True,
            arguments=("after-reboot",), disk_fixture=snapshot)
        output = ROOT / "build/test-out"
        boots = [json.loads((output / name).read_text()) for name in
                 ("shared-memory-qemu.boot-image.json", "shared-memory-reboot-qemu.boot-image.json")]
        if boots[0] != boots[1]:
            raise RuntimeError("Shared-memory tests used different boot images")
        (output / "shared-memory.acceptance.json").write_text(json.dumps({
            "scope": "Native named shared-memory API; complete Gecko/Zen remains unverified",
            "cpus": 8, "shared_updates": 512, "exclusive_creation": True,
            "unlink_retains_handles_and_mappings": True, "recreated_name_is_distinct": True,
            "readonly_child_mapping": True, "cloexec": True, "killed_creator": True,
            "descriptor_admission_precedes_creation": True, "namespace_resets_on_reboot": True,
            "elf_sha256": hashlib.sha256((ROOT / "build/user/shared_memory_test.elf").read_bytes()).hexdigest(),
            "boot": boots[0],
        }, indent=2) + "\n")
