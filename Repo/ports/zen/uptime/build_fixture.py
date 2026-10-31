#!/usr/bin/env python3
"""Link the real uptime fixture against staged or integrated native wrappers."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
STATE = ROOT / "build/ports/zen/process-uptime"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--staged", action="store_true")
args = parser.parse_args()
objects = json.loads((ROOT / "ports/zen/upstream/alix-toolchain/runtime-objects.json").read_text())
flags = []
if args.staged:
    replacement = STATE / "objects/user_lib_syscall.c.o"
    if not replacement.is_file(): raise RuntimeError("compile staged uptime first")
    objects = [str(replacement) if Path(value).resolve() == (ROOT / "build/user/lib/syscall.o").resolve() else value
               for value in objects]
    flags += ["-iquote", str(STATE / "objects/user-headers"), "-I" + str(STATE / "objects/include")]
STATE.mkdir(parents=True, exist_ok=True)
manifest = STATE / "fixture-runtime.json"
manifest.write_text(json.dumps(objects, indent=2) + "\n")
env = os.environ.copy(); env["ALIX_RUNTIME_MANIFEST"] = str(manifest)
output = ROOT / "build/user/process_uptime_test.elf"
subprocess.run([str(ROOT / "ports/zen/toolchain/alix-clang"), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                *flags, str(ROOT / "tests/process_uptime_test.c"), "-o", str(output)], env=env, check=True)
if subprocess.check_output(["x86_64-elf-nm", "--undefined-only", str(output)], text=True).strip():
    raise RuntimeError("uptime fixture contains unresolved symbols")
print(f"Native uptime fixture linked ({'staged' if args.staged else 'integrated'}): {output}")
