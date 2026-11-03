#!/usr/bin/env python3
"""Shared file memory, cross-process ownership and an independent disk remount."""
from pathlib import Path
import tempfile
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == '__main__':
    output=ROOT/'build/test-out'
    with tempfile.TemporaryDirectory(prefix='alix-file-map-') as directory:
        blank=Path(directory)/'blank.img';snapshot=Path(directory)/'persisted.img'
        with blank.open('wb') as stream:stream.truncate(64*1024*1024)
        run_native_elf('file_mapping_test.elf',
            ('FILE_MAPPING_TEST: PASS cpus=8 atomic_updates=512 aliases=1 private=1 close=1 offset=1 permissions=1 split=1 process=1 killed_owner=1 coherence=1 msync=1 tail=1',),
            output/'file-mapping-qemu.log','Native shared file mappings',130,
            expected_wait_status=0,fail_on_missing_markers_at_exit=True,
            disk_fixture=blank,disk_snapshot=snapshot,
            setup_commands=(('mkfs /dev/ahci1','mkfs complete'),('mount /dev/ahci1 /tmp/map-disk','mount complete')))
        run_native_elf('file_mapping_test.elf',('FILE_MAPPING_REMOUNT: PASS bytes=32785 msync=1 fsync=0',),
            output/'file-mapping-remount-qemu.log','Mapped files independent remount',50,
            arguments=('read',),disk_fixture=snapshot,expected_wait_status=0,fail_on_missing_markers_at_exit=True)
    run_native_elf('file_mapping_legacy_test.elf',('FILE_MAPPING_LEGACY: PASS unsupported=1 anonymous_sync=1',),
        output/'file-mapping-legacy-qemu.log','Legacy mapping namespace isolation',40,
        expected_wait_status=0,fail_on_missing_markers_at_exit=True)
