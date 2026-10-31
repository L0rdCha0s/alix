#!/usr/bin/env python3
"""Compile the staged uptime implementation and its actual integration units."""
from pathlib import Path
import subprocess
import shutil

ROOT = Path(__file__).resolve().parents[3]
STAGE = ROOT / "build/ports/zen/process-uptime/pending"
OUT = STAGE.parent / "objects"
OUT.mkdir(exist_ok=True)
shutil.copytree(ROOT / "include", OUT / "include", dirs_exist_ok=True)
shutil.copytree(STAGE / "include", OUT / "include", dirs_exist_ok=True)
shutil.copytree(ROOT / "user/lib", OUT / "user-headers", ignore=shutil.ignore_patterns("*.c", "*.cpp", "*.S", "*.ld"), dirs_exist_ok=True)
shutil.copytree(STAGE / "user/lib", OUT / "user-headers", ignore=shutil.ignore_patterns("*.c"), dirs_exist_ok=True)
common = ["x86_64-elf-gcc", "-std=c11", "-O2", "-ffreestanding", "-fno-stack-protector", "-fno-builtin",
          "-fno-pic", "-m64", "-mno-red-zone", "-Wall", "-Wextra", "-Werror", "-g", "-fshort-wchar",
          "-I" + str(OUT / "include"), "-I" + str(ROOT / "src/atk")]
for source in sorted(STAGE.rglob("*.c")):
    user = "user" in source.relative_to(STAGE).parts
    flags = ["-msse2", "-mfpmath=sse", "-mstackrealign", "-mcmodel=large", "-DNORMALUNIX",
             "-DATK_NO_DESKTOP_APPS", "-I" + str(OUT / "user-headers"), "-I" + str(ROOT / "user")] if user else [
             "-mgeneral-regs-only", "-mfpmath=387", "-mno-sse", "-DKERNEL_BUILD"]
    output = OUT / ("_".join(source.relative_to(STAGE).parts) + ".o")
    subprocess.run([*common, *flags, "-c", str(source), "-o", str(output)], check=True, cwd=ROOT)
print("Staged native uptime kernel, constructor, dispatcher and user wrapper: compile PASS")
