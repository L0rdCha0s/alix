#!/usr/bin/env python3
"""Verify the upstream compiler driver emits native Alix ELF with its runtime."""
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    objects = shlex.split(os.environ.get("ALIX_RUNTIME_OBJECTS", ""))
    if not objects:
        raise RuntimeError("use make zen-toolchain-test to provide Alix runtime objects")
    state = ROOT / "ports/zen/upstream/alix-toolchain"
    state.mkdir(parents=True, exist_ok=True)
    manifest = state / "runtime-objects.json"
    temporary_manifest = manifest.with_name(f".{manifest.name}.{os.getpid()}.tmp")
    temporary_manifest.write_text(json.dumps([str((ROOT / obj).resolve()) for obj in objects], indent=2) + "\n")
    temporary_manifest.replace(manifest)
    env = os.environ.copy()
    env["ALIX_RUNTIME_MANIFEST"] = str(manifest)
    compiler = ROOT / "ports/zen/toolchain/alix-clang"
    macros = subprocess.check_output([str(compiler), "-dM", "-E", "-x", "c", "/dev/null"], env=env, text=True)
    for required in ("#define __ALIX__ 1", "#define __ELF__ 1", "#define __x86_64__ 1"):
        if required not in macros:
            raise RuntimeError(f"native compiler identity is missing {required}")
    if "#define __linux__" in macros or "#define __APPLE__" in macros:
        raise RuntimeError("target compiler inherited host/Linux OS identity")
    dry_run = subprocess.run([str(compiler) + "++", "-###", "-x", "c++", "/dev/null"],
                             env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             check=True).stdout
    for required in ("-nostdlib", "-static", "user/lib/link.ld", "crt0.o", "libc++.a"):
        if required not in dry_run:
            raise RuntimeError(f"compiler link dry run omits native runtime input {required}")
    with tempfile.TemporaryDirectory(prefix="alix-cxx-header-order-") as directory:
        wrappers = Path(directory)
        (wrappers / "complex").write_text(
            '#pragma GCC system_header\n#pragma GCC visibility push(default)\n'
            '#define ALIX_TEST_WRAPPER_VISITED 1\n#include_next <complex>\n'
            '#pragma GCC visibility pop\n')
        hidden = wrappers / "hidden.h"
        hidden.write_text('#pragma GCC visibility push(hidden)\n')
        probe = '#include <complex>\n#ifndef ALIX_TEST_WRAPPER_VISITED\n#error consumer system wrapper bypassed\n#endif\n#include <sstream>\n#include <system_error>\n'
        subprocess.run([str(compiler) + "++", "-std=c++20", "-I" + str(wrappers),
                        "-include", str(hidden), "-fsyntax-only", "-x", "c++", "-"],
                       env=env, text=True, input=probe, check=True)
    output = ROOT / "build/user/alix_toolchain_test.elf"
    output.parent.mkdir(parents=True, exist_ok=True)
    log = ROOT / "build/ports/zen/toolchain-link.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    source = r'''
#include <vector>
#include "serial.h"
#include "stdio.h"
#include "unistd.h"
#include <cmath>
#include <cstdlib>
static __thread int value = 42;
extern "C" void abort(void) {
    serial_printf("ALIX_ABORT_OVERRIDE: PASS\n");
    _Exit(77);
}
int main(int argc, char**) {
    if (argc > 1) abort();
    std::vector<int> values{1, 2, 3};
    bool okay = values.at(0) + values.at(1) + values.at(2) == 6 && value == 42 && getpid() > 0;
    volatile double number = 0.25;
    okay = std::sin(number) > 0.24 && std::sin(number) < 0.25 && okay;
    okay = puts("ALIX_TOOLCHAIN_STDIO: line") >= 0 && okay;
    serial_printf("ALIX_TOOLCHAIN_TEST: %s\n", okay ? "PASS" : "FAIL");
    return okay ? 0 : 1;
}
'''
    with log.open("w") as stream:
        result = subprocess.run([str(compiler) + "++", "-std=c++20", "-x", "c++", "-",
                                 "-pie", "-lm", "-o", str(output)], input=source, text=True, env=env,
                                stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("native driver failed to link:\n" + "\n".join(log.read_text().splitlines()[-40:]))
    data = output.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError("driver output is not little-endian ELF64")
    kind, machine = struct.unpack_from("<HH", data, 16)
    if kind != 2 or machine != 62:
        raise RuntimeError("driver output is not native x86-64 ET_EXEC")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phcount = struct.unpack_from("<HH", data, 54)
    types = [struct.unpack_from("<I", data, phoff + index * phsize)[0] for index in range(phcount)]
    if 7 not in types or 3 in types:
        raise RuntimeError("native static TLS startup contract is missing or a host interpreter was linked")
    undefined = subprocess.check_output(["x86_64-elf-nm", "--undefined-only", str(output)], text=True)
    if undefined.strip():
        raise RuntimeError("unresolved native runtime symbols: " + undefined)
    symbols = subprocess.check_output(["x86_64-elf-nm", "--defined-only", str(output)], text=True)
    if not any(line.split()[-2:] == ["T", "abort"] for line in symbols.splitlines()):
        raise RuntimeError("application abort hook did not override the upstream runtime's weak default")
    print(f"Native Alix compiler identity/link test: PASS ({output})")
    print("This proves compilation/linking only; the ELF must run in Alix before claiming execution.")


if __name__ == "__main__":
    main()
