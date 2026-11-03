#!/usr/bin/env python3
"""Check SSP code generation, shared-runtime exports and preinit ordering."""
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def run(arguments, **options):
    return subprocess.check_output(list(map(str, arguments)), text=True, **options)


def main():
    objects = shlex.split(os.environ.get("ALIX_RUNTIME_OBJECTS", ""))
    if not objects:
        raise RuntimeError("use make zen-ssp-test to provide Alix runtime objects")
    state = ROOT / "ports/zen/upstream/alix-toolchain"
    state.mkdir(parents=True, exist_ok=True)
    manifest = state / "runtime-objects.json"
    temporary_manifest = manifest.with_name(f".{manifest.name}.{os.getpid()}.tmp")
    temporary_manifest.write_text(json.dumps([str((ROOT / obj).resolve()) for obj in objects], indent=2) + "\n")
    temporary_manifest.replace(manifest)
    env = os.environ.copy()
    env["ALIX_RUNTIME_MANIFEST"] = str(manifest)
    compiler = ROOT / "ports/zen/toolchain/alix-clang"
    output = ROOT / "build/user/stack_protector_test.elf"
    object_file = ROOT / "build/user/tests/stack_protector_test.o"
    object_file.parent.mkdir(parents=True, exist_ok=True)
    run([compiler, "-O2", "-fstack-protector-strong", "-c", ROOT / "tests/stack_protector_test.c",
         "-o", object_file], env=env)
    assembly = run(["x86_64-elf-objdump", "-dr", object_file])
    for symbol in ("__stack_chk_guard", "__stack_chk_fail"):
        if symbol not in assembly:
            raise RuntimeError("real compiler did not emit " + symbol)
    if "%fs:" in assembly:
        raise RuntimeError("compiler emitted a foreign TLS canary ABI")
    run([compiler, object_file, "-o", output], env=env)
    if run(["x86_64-elf-nm", "--undefined-only", output]).strip():
        raise RuntimeError("native stack-protector fixture has unresolved symbols")
    symbols = {}
    for line in run(["x86_64-elf-nm", output]).splitlines():
        fields = line.split()
        if len(fields) == 3:
            symbols[fields[2]] = int(fields[0], 16)
    data = output.read_bytes()
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_size, section_count, names_index = struct.unpack_from("<HHH", data, 58)
    headers = [section_offset + index * section_size for index in range(section_count)]
    names_offset, names_size = struct.unpack_from("<QQ", data, headers[names_index] + 24)
    names = data[names_offset:names_offset + names_size]
    preinit = None
    for header in headers:
        name_offset = struct.unpack_from("<I", data, header)[0]
        if names[name_offset:].split(b"\0", 1)[0] == b".preinit_array":
            offset, size = struct.unpack_from("<QQ", data, header + 24)
            preinit = struct.unpack_from("<" + "Q" * (size // 8), data, offset)
    # The uninstrumented ELF TLS fixup is loader bootstrap, before the SSP
    # initializer. Both must precede every ordinary user preinit callback.
    expected = tuple(symbols[name] for name in
                     ("dl_main_startup", "stack_protector_initialize", "preinitialize"))
    if preinit != expected:
        raise RuntimeError("SSP guard initialization does not precede ordinary preinit")
    unprotected = ROOT / "build/user/stack_protector_unprotected_test.elf"
    source = '#include "serial.h"\n#include "dlfcn.h"\n#include "stdint.h"\nint main(void) { uintptr_t *guard=dlsym(RTLD_DEFAULT,"__stack_chk_guard"); if(!guard||!*guard)return 1; serial_printf("STACK_PROTECTOR_UNPROTECTED: PASS\\n"); return 0; }\n'
    plain_object=ROOT/"build/user/tests/stack_protector_unprotected_test.o"
    run([compiler,"-fno-stack-protector","-x","c","-","-c","-o",plain_object],env=env,input=source)
    if "__stack_chk_" in run(["x86_64-elf-objdump","-dr",plain_object]):
        raise RuntimeError("unprotected object acquired compiler canary instrumentation")
    run([compiler,plain_object,"-o",unprotected],env=env)
    exported=run(["x86_64-elf-readelf","--dyn-syms","--wide",unprotected])
    for symbol in ("__stack_chk_guard","__stack_chk_fail"):
        if not any(symbol in line and "DEFAULT" in line and "UND" not in line for line in exported.splitlines()):
            raise RuntimeError("upstream executable did not retain shared SSP runtime: "+symbol)
    print("Native Alix SSP code generation, protected-library exports and runtime-preinit order: PASS")
    print(f"Execution remains to be checked in Alix: {output}")


if __name__ == "__main__":
    main()
