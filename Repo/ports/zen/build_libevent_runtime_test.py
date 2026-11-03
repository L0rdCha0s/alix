#!/usr/bin/env python3
"""Link Gecko's actual configured native libevent object into acceptance ELF."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "ports/zen/upstream/firefox-159.0"
OBJECT_DIR = ROOT / "ports/zen/upstream/obj-gecko-alix/ipc/chromium/src/third_party"
OUT = ROOT / "build/ports/zen/libevent-runtime"
OUT.mkdir(parents=True, exist_ok=True)
subprocess.run(["make", "-C", str(OBJECT_DIR), "-j2", "compile"], check=True)
objects = sorted(OBJECT_DIR.glob("Unified_c_*.o"))
if len(objects) != 1:
    raise RuntimeError("expected the configured native libevent core object")
includes = ["-I" + str(ENGINE / "ipc/chromium/src/third_party/libevent" / name)
            for name in ("alix", "include", "compat")]
elf = ROOT / "build/user/libevent_runtime_test.elf"
subprocess.run([str(ROOT / "ports/zen/toolchain/alix-clang"), "-std=gnu11", "-O2", "-g",
                *includes, str(ROOT / "tests/libevent_runtime_test.c"), *map(str, objects),
                "-o", str(elf)], check=True)
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
(OUT / "native-link.json").write_text(json.dumps({
    "scope": "Actual configured Gecko libevent core object; guest execution separate",
    "objects": [{"path": str(path), "sha256": digest(path)} for path in objects],
    "elf": str(elf), "elf_sha256": digest(elf),
}, indent=2) + "\n")
print("Actual native Gecko libevent acceptance ELF:", elf)
