#!/usr/bin/env python3
import sys
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import ROOT, run_native_elf
if __name__ == "__main__":
    run_native_elf("base_elf_rss_test.elf",
        ("BASE_ELF_RSS_TEST: PASS cpus=8 auxv=1 phdr=1 callback_close=1 nested=1 notes=1 rss_pages=1024 legacy_abi=1",),
        ROOT / "build/test-out/base-elf-rss-qemu.log", "native ELF metadata and resident memory accounting", 180,
        input_files=(("libalix-phdr.so", ROOT / "build/ports/zen/elf-metadata/libalix-phdr.so"),),
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
