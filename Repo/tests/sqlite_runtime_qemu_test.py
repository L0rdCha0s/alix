#!/usr/bin/env python3
"""Actual configured SQLite rollback/WAL/concurrency and independent disk readback."""
from pathlib import Path
import tempfile
import json
from cpp_runtime_qemu_test import ROOT,run_native_elf

if __name__=='__main__':
    with tempfile.TemporaryDirectory(prefix='alix-sqlite-') as temporary:
        library=ROOT/'ports/zen/upstream/obj-gecko-alix/dist/bin/libmozsqlite3.so'
        disk=Path(temporary)/'blank.img';snapshot=Path(temporary)/'committed.img'
        with disk.open('wb') as stream:stream.truncate(64*1024*1024)
        run_native_elf('sqlite_runtime_test.elf',(
            'SQLITE_RUNTIME_TEST: PASS cpus=8 rows=198 rollback=1 wal=1 snapshot=1 cross_process=1 busy=1 integrity=1 commit=1 full_library=1 fts5=1 vectors=1',
        ),ROOT/'build/test-out/sqlite-runtime-qemu.log','Actual Gecko SQLite in Alix',240,
            expected_wait_status=0,fail_on_missing_markers_at_exit=True,download_timeout_seconds=60,
            disk_fixture=disk,disk_snapshot=snapshot,input_files=((library.name,library),),
            setup_commands=(('mkfs /dev/ahci1','mkfs complete'),('mount /dev/ahci1 /tmp/sqlite-disk','mount complete')))
        run_native_elf('sqlite_runtime_test.elf',('SQLITE_REMOUNT_TEST: PASS rows=198 integrity=1 readonly=1 full_library=1 fts5=1 vectors=1',),
            ROOT/'build/test-out/sqlite-remount-qemu.log','SQLite independent read-only remount',90,
            expected_wait_status=0,fail_on_missing_markers_at_exit=True,download_timeout_seconds=60,
            disk_fixture=snapshot,arguments=('read',),input_files=((library.name,library),))
        output=ROOT/'build/test-out'
        boots=[json.loads((output/name).read_text()) for name in
               ('sqlite-runtime-qemu.boot-image.json','sqlite-remount-qemu.boot-image.json')]
        if boots[0]!=boots[1]:raise RuntimeError('SQLite boots used different kernel/loader/user images')
        (output/'sqlite-runtime.acceptance.json').write_text(json.dumps({
            'scope':'Actual configured Gecko SQLite shared library; complete browser remains separate',
            'full_library':True,'fts5':True,'vectors':True,
            'cpus':8,'rows_read_after_remount':198,'rollback':True,'wal':True,'snapshot_isolation':True,
            'cross_process_busy_and_commit':True,'integrity_check':'ok',
            'link':json.loads((ROOT/'build/ports/zen/sqlite-native-link.json').read_text()),'boot':boots[0],
        },indent=2)+'\n')
