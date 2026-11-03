#!/usr/bin/env python3
from cpp_runtime_qemu_test import ROOT,run_native_elf
import json

if __name__=='__main__':
    directory=ROOT/'build/ports/zen/version-loader'
    run_native_elf('version_loader_test.elf',(
        'VERSION_LOADER_TEST: PASS cpus=8 tls_updates=1024 default=1 legacy=1 data=1 requirements=1 missing_rejected=1 constructors=1 unload=1',
    ),ROOT/'build/test-out/version-loader-qemu.log','Native versioned ELF loading',150,
        input_files=tuple((name,directory/name)for name in ('libversion_provider.so','libversion_consumer.so','libversion_bad.so')),
        expected_wait_status=0,fail_on_missing_markers_at_exit=True)
    log=ROOT/'build/test-out/version-loader-qemu.log'
    log.with_suffix('.acceptance.json').write_text(json.dumps({
        'scope':'Native ELF version definitions/requirements, aliases, data and dynamic TLS; complete browser separate',
        'cpus':8,'tls_updates':1024,'default_and_legacy_aliases':True,'missing_requirement_rejected_before_constructors':True,
        'provider_unloaded_after_tls_cleanup':True,'boot':json.loads(log.with_suffix('.boot-image.json').read_text()),
        'link':json.loads((directory/'native-link.json').read_text()),
    },indent=2)+'\n')
