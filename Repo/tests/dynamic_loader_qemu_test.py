#!/usr/bin/env python3
"""Execute actual ELF DSOs, dependencies and dynamic TLS in eight-CPU Alix."""
from cpp_runtime_qemu_test import ROOT,run_native_elf
if __name__=='__main__':
    directory=ROOT/'build/ports/zen/dynamic-loader'
    names=('libalix-loader-dep.so','libalix-loader-plugin.so','libalix-loader-unresolved.so','loader-bad.elf','libalix-loader-provider.so','libalix-loader-consumer.so')
    run_native_elf('dynamic_loader_test.elf',
        ('DYNAMIC_LOADER_TEST: PASS cpus=8 tls_updates=512 elf=1 imports=1 dependencies=1 constructors=1 finalizers=1 scopes=1 errors=1 unload=1',
         'DYNAMIC_LOADER_EXIT: PASS nodelete=1 finalizers=1'),
        ROOT/'build/test-out/dynamic-loader-qemu.log','Native ELF dynamic loading',100,
        input_files=tuple((name,directory/name) for name in names),
        expected_wait_status=0,fail_on_missing_markers_at_exit=True)
    run_native_elf('dynamic_loader_test.elf',
        ('DYNAMIC_LOADER_DTORS: PASS cpus=8 dtors=8 deferred_unload=1 code_lifetime=1 finalizer=1',),
        ROOT/'build/test-out/dynamic-loader-dtors-qemu.log','Native DSO destructor lifetime',70,
        arguments=('destructors',),input_files=(('libalix-loader-destructor.so',directory/'libalix-loader-destructor.so'),),
        expected_wait_status=0,fail_on_missing_markers_at_exit=True)
    run_native_elf('dynamic_loader_test.elf',('DYNAMIC_LOADER_PIN_EXIT: PASS finalizer=1 code_resident=1',),
        ROOT/'build/test-out/dynamic-loader-pinned-exit-qemu.log','Native DSO finalization with live threads',70,
        arguments=('exit-with-pins',),input_files=(('libalix-loader-destructor.so',directory/'libalix-loader-destructor.so'),),
        expected_wait_status=0,fail_on_missing_markers_at_exit=True)
    for mode in ('relro','text'):
        run_native_elf('dynamic_loader_test.elf',('VM_FAULT_TEST: armed write',),
            ROOT/f'build/test-out/dynamic-loader-{mode}-qemu.log',f'Native DSO {mode} write protection',50,
            arguments=('fault-'+mode,),input_files=tuple((name,directory/name) for name in names),expected_fault=7)
