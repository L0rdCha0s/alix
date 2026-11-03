#!/usr/bin/env python3
"""Link real Gecko RLBox memory/minWASI with the actual WABT runtime."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "ports/zen/upstream/firefox-159.0"
OBJ = ROOT / "ports/zen/upstream/obj-gecko-alix"
OUT = ROOT / "build/ports/zen/rlbox-runtime"
OUT.mkdir(parents=True, exist_ok=True)
compiler = ROOT / "ports/zen/toolchain/alix-clang"
includes = ["-I" + str(ENGINE / "third_party/wasm2c/wasm2c"),
            "-I" + str(ENGINE / "third_party/rlbox_wasm2c_sandbox/include")]
# The acceptance executable uses WABT's real default trap/unwind implementation;
# Firefox's configured objects instead route fatal traps through mozglue.
flags = ["-DWASM_RT_USE_MMAP=1", "-DWASM_RT_SKIP_SIGNAL_RECOVERY=1",
         "-DWASM_RT_NONCONFORMING_UNCHECKED_STACK_EXHAUSTION=1", "-DWASM_RT_ALLOW_SEGUE=0"]
subprocess.run(["make", "-C", str(OBJ / "config/external/rlbox_wasm2c_sandbox"), "-j2", "compile"], check=True)
objects = [OBJ / "config/external/rlbox_wasm2c_sandbox" / name
           for name in ("wasm2c_rt_mem.o", "wasm2c_rt_minwasi.o")]
for source in ("wasm-rt-impl.c", "wasm-rt-mem-impl.c"):
    output = OUT / (Path(source).stem + ".o")
    subprocess.run([str(compiler), "-std=c11", "-O2", "-g", *flags, *includes, "-c",
                    str(ENGINE / "third_party/wasm2c/wasm2c" / source), "-o", str(output)], check=True)
    objects.append(output)
elf = ROOT / "build/user/rlbox_runtime_test.elf"
subprocess.run([str(compiler), "-std=c11", "-O2", "-g", *flags, *includes,
                str(ROOT / "tests/rlbox_runtime_test.c"), *map(str, objects), "-o", str(elf)], check=True)
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
(OUT / "native-link.json").write_text(json.dumps({
    "scope": "Actual configured RLBox memory/minWASI objects and default WABT trap/runtime; guest execution separate",
    "flags": flags, "objects": [{"path": str(path), "sha256": digest(path)} for path in objects],
    "elf": str(elf), "elf_sha256": digest(elf),
}, indent=2) + "\n")
print("Actual native RLBox/WABT acceptance ELF:", elf)
