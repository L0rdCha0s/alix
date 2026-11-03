#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("base_accounts_inet_test.elf",
        ("BASE_ACCOUNTS_INET_TEST: PASS cpus=8 lookups=1024 legacy_ipv4=10 invalid_ipv4=12 tls_storage=1 byte_order=1",),
        ROOT / "build/test-out/base-accounts-inet-qemu.log", "native account and IPv4 compatibility APIs", 160,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
