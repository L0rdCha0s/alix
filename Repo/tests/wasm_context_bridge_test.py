#!/usr/bin/env python3
"""Compile Gecko's actual Alix context macros against the native signal ABI."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "ports/zen/upstream/firefox-159.0/js/src/wasm/WasmSignalHandlers.cpp").read_text()
branch = source.split("#  elif defined(__ALIX__)\n", 1)[1].split("#  elif", 1)[0]
assert "uc_mcontext.gregs" not in branch
program = '#include <sys/ucontext.h>\n#include <stddef.h>\n' + branch + r'''
static_assert(sizeof(ucontext_t) == 768);
static_assert(sizeof(mcontext_t) == 704);
static_assert(offsetof(mcontext_t, fpregs) == 192);
static_assert(sizeof(RIP_sig((ucontext_t*)0)) == sizeof(void*));
static_assert(sizeof(RSP_sig((ucontext_t*)0)) == sizeof(void*));
static_assert(sizeof(RBP_sig((ucontext_t*)0)) == sizeof(void*));
void edit_native_context(ucontext_t *context, unsigned long pc, unsigned long sp,
                         unsigned long bp) {
    RIP_sig(context) = pc; RSP_sig(context) = sp; RBP_sig(context) = bp;
}
'''
with tempfile.TemporaryDirectory(prefix="alix-wasm-context-") as temporary:
    path = Path(temporary)
    (path / "bridge.cpp").write_text(program)
    subprocess.run([str(ROOT / "ports/zen/toolchain/alix-clang++"), "-std=c++20", "-O2",
                    "-Wall", "-Wextra", "-Werror", "-c", str(path / "bridge.cpp"),
                    "-o", str(path / "bridge.o")], check=True)
print("Actual Gecko Alix context bridge: native field widths, offsets and writable access PASS")
