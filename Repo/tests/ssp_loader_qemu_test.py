#!/usr/bin/env python3
from cpp_runtime_qemu_test import ROOT,run_native_elf
plugin=ROOT/'build/ports/zen/ssp-loader/libalix-ssp-plugin.so'
if __name__=='__main__':
    run_native_elf('ssp_loader_test.elf',
        ('SSP_LOADER_TEST: PASS cpus=8 calls=512 shared_guard=1 constructor=1 environment=1',),
        ROOT/'build/test-out/ssp-loader-qemu.log','Protected native shared library',70,
        input_files=((plugin.name,plugin),),expected_wait_status=0,fail_on_missing_markers_at_exit=True)
    run_native_elf('ssp_loader_test.elf',
        ('SSP_LOADER_TEST: corrupt armed','ALIX_STACK_PROTECTOR: stack corruption'),
        ROOT/'build/test-out/ssp-loader-corrupt-qemu.log','Protected DSO stack corruption',50,
        arguments=('corrupt',),input_files=((plugin.name,plugin),),expected_wait_status=127<<8,
        fail_on_missing_markers_at_exit=True,forbidden_markers=('SSP_LOADER_TEST: PASS',))
