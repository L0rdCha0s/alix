#!/usr/bin/env python3
"""Link a genuine Alix ELF against the native CRT/libc, never host libraries."""
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[3]
objects = os.environ.get("ALIX_RUNTIME_OBJECTS", "").split()
if not objects:
    raise SystemExit("ALIX_RUNTIME_OBJECTS must name the native Alix runtime objects")
linker = shutil.which("x86_64-elf-ld")
libgcc = subprocess.check_output(["x86_64-elf-gcc", "-print-libgcc-file-name"], text=True).strip()
arguments = sys.argv[1:]
if arguments[:2] == ["-flavor", "gnu"]:
    arguments = arguments[2:]
os.execv(linker, [linker, "-T", str(root / "user/lib/link.ld"),
                 *[str(root / item) for item in objects], *arguments, libgcc])
