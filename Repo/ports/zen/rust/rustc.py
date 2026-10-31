#!/usr/bin/env python3
"""Use the real compiler with the isolated matching Alix std-source sysroot."""
import os
from pathlib import Path
import shutil
import sys

sysroot = Path(__file__).resolve().parents[1] / "upstream/rust-alix-sysroot"
default_specification = Path(__file__).resolve().with_name("x86_64-unknown-alix.json")
specification = Path(os.environ.get("RUST_TARGET_SPEC", str(default_specification))).resolve()
if specification.name != default_specification.name or not specification.is_file():
    sys.exit("RUST_TARGET_SPEC must name an existing x86_64-unknown-alix.json file")
compiler = os.environ.get("ALIX_REAL_RUSTC") or shutil.which("rustc")
arguments = sys.argv[1:]
filtered = []
skip = False
for arg in arguments:
    if skip:
        skip = False
        continue
    if arg == "--sysroot":
        skip = True
    elif not arg.startswith("--sysroot="):
        filtered.append(arg)
native_target = False
for index, argument in enumerate(filtered):
    if argument == "--target" and index + 1 < len(filtered):
        selected = filtered[index + 1]
        if selected == "x86_64-unknown-alix":
            filtered[index + 1] = str(specification)
            native_target = True
        elif Path(selected).resolve() in (specification, default_specification):
            native_target = True
    elif argument.startswith("--target="):
        selected = argument.split("=", 1)[1]
        if selected == "x86_64-unknown-alix":
            filtered[index] = "--target=" + str(specification)
            native_target = True
        elif Path(selected).resolve() in (specification, default_specification):
            native_target = True
if native_target:
    # This is a declared custom target, not an upstream built-in. In particular
    # --print target-list remains the compiler's unmodified built-in list.
    os.environ.setdefault("RUSTC_BOOTSTRAP", "1")
    os.environ["RUST_TARGET_PATH"] = str(specification.parent)
    if "-Zunstable-options" not in filtered:
        filtered.append("-Zunstable-options")
os.execv(compiler, [compiler, "--sysroot", str(sysroot), *filtered])
