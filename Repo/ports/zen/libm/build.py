#!/usr/bin/env python3
"""Build optional native Alix libm from the pinned LLVM libc implementation."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ports/zen/upstream/llvm-project-22.1.8"
BUILD = ROOT / "ports/zen/upstream/libm-alix-build"
REVISION = "ca7933e47d3a3451d81e72ac174dcb5aa28b59d1"

def main():
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip()
    if revision != REVISION:
        raise RuntimeError("LLVM libc source does not match the pinned revision")
    objects = BUILD / "objects"
    library = BUILD / "lib"
    objects.mkdir(parents=True, exist_ok=True)
    library.mkdir(exist_ok=True)
    outputs = []
    for name in ("llvm_nearbyint", "llvm_math"):
        output = objects / (name + ".o")
        subprocess.run([str(ROOT / "ports/zen/toolchain/alix-clang++"), "-std=c++20", "-O2", "-g",
                        "-frounding-math", "-fno-exceptions", "-fno-rtti",
                        "-I" + str(SOURCE / "libc"), "-DLIBC_NAMESPACE=alix_llvm_libc", "-c",
                        str(ROOT / "user/lib" / (name + ".cpp")), "-o", str(output)], check=True)
        outputs.append(output)
    archive = library / "libalix-math.a"
    temporary = archive.with_name(f".{archive.name}.{os.getpid()}.tmp")
    llvm = Path(os.environ.get("ALIX_LLVM_PREFIX", "/opt/homebrew/opt/llvm"))
    subprocess.run([str(llvm / "bin/llvm-ar"), "rcs", str(temporary), *map(str, outputs)], check=True)
    temporary.replace(archive)
    print(f"Native LLVM-backed Alix libm archive: {archive}")

if __name__ == "__main__": main()
