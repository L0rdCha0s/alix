#!/usr/bin/env python3
"""Check the independent ISO C11 function inventory against real runtime objects."""
from pathlib import Path
import json
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    inventory = json.loads((ROOT / "tests/fixtures/libc_c11_functions.json").read_text())
    expected = {name for names in inventory["headers"].values() for name in names}
    objects = json.loads(subprocess.check_output(
        ["make", "-s", "libc-runtime-manifest"], cwd=ROOT, text=True))
    defined = subprocess.check_output(
        ["x86_64-elf-nm", "-g", "--defined-only", *objects], cwd=ROOT, text=True)
    symbols = set(re.findall(r"^\w+ [TW] (\w+)$", defined, re.M))
    missing = sorted(expected - symbols)
    if missing:
        raise RuntimeError("missing runtime implementations: " + ", ".join(missing))
    source = "\n".join(f"#include <{header}>" for header in inventory["headers"])
    source += "\n#include <stdint.h>\nconst uintptr_t interfaces[] = {\n"
    source += ",\n".join(f"    (uintptr_t)&{name}" for name in sorted(expected))
    source += "\n};\n"
    with tempfile.TemporaryDirectory(prefix="alix-c11-api-") as directory:
        path = Path(directory) / "interfaces.c"
        path.write_text(source)
        subprocess.run(["x86_64-elf-gcc", "-std=c11", "-ffreestanding", "-fshort-wchar",
                        "-fsyntax-only", "-Wall", "-Wextra", "-Iinclude", str(path)],
                       cwd=ROOT, check=True)
    print(f"C11_API_TEST: PASS {len(expected)}/{len(expected)} runtime functions and public declarations")


if __name__ == "__main__":
    main()
