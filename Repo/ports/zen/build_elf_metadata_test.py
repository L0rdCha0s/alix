#!/usr/bin/env python3
from pathlib import Path
import subprocess
ROOT = Path(__file__).resolve().parents[2]
out = ROOT / "build/ports/zen/elf-metadata"
out.mkdir(parents=True, exist_ok=True)
compiler = str(ROOT / "ports/zen/toolchain/alix-clang")
subprocess.run([compiler, "-shared", "-fPIC", "-O2", str(ROOT / "tests/phdr_fixture.c"),
                "-Wl,--build-id=sha1", "-Wl,-soname,libalix-phdr.so", "-o", str(out / "libalix-phdr.so")], check=True)
subprocess.run([compiler, "-O2", "-g", str(ROOT / "tests/base_elf_rss_test.c"),
                "-o", str(ROOT / "build/user/base_elf_rss_test.elf")], check=True)
