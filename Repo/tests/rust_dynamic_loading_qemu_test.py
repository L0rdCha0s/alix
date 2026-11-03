#!/usr/bin/env python3
from cpp_runtime_qemu_test import ROOT,run_native_elf
if __name__=='__main__':
    plugin=ROOT/'build/ports/zen/rust-dynamic-loading/libalix-rust-loader.so'
    run_native_elf('rust_dynamic_loading_test.elf',
        ('RUST_DYNAMIC_LOADING_TEST: PASS cpus=8 tls_updates=512 libloading=1 ash=1 imports=1 null_symbol=1 errors=1 unload=1',),
        ROOT/'build/test-out/rust-dynamic-loading-qemu.log','Rust native dynamic loading',100,
        input_files=((plugin.name,plugin),),expected_wait_status=0,fail_on_missing_markers_at_exit=True)
