#!/usr/bin/env python3
"""Package Alix's complete vendored native math runtime for upstream consumers."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
BUILD = ROOT / "ports/zen/upstream/libm-alix-build"


def main():
    subprocess.run(["make", "libc-runtime-objects"], cwd=ROOT, check=True)
    objects = json.loads(subprocess.check_output(
        ["make", "-s", "libc-runtime-manifest"], cwd=ROOT, text=True))
    selected = [str(ROOT / path) for path in objects if
                "/vendor/musl/math/" in path or "/vendor/musl/complex/" in path or
                "/vendor/freebsd/" in path or
                Path(path).name in {"math.o", "math_errno.o", "fenv.o", "compiler_complex.o"}]
    library = BUILD / "lib"
    library.mkdir(parents=True, exist_ok=True)
    archive = library / "libalix-math.a"
    temporary = archive.with_name(f".{archive.name}.{os.getpid()}.tmp")
    subprocess.run(["x86_64-elf-ar", "rcs", str(temporary), *selected], check=True)
    temporary.replace(archive)
    print(f"Complete native Alix math archive: {archive} ({len(selected)} objects)")


if __name__ == "__main__":
    main()
