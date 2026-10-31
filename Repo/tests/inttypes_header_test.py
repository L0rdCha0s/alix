#!/usr/bin/env python3
"""Check every PRI/SCN macro against actual GCC and Clang target types."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    calls = []
    for family in ("", "LEAST", "FAST", "MAX", "PTR"):
        for width in ((None,) if family in ("MAX", "PTR") else (8, 16, 32, 64)):
            if family == "MAX":
                signed, unsigned, suffix = "intmax_t", "uintmax_t", "MAX"
            elif family == "PTR":
                signed, unsigned, suffix = "intptr_t", "uintptr_t", "PTR"
            else:
                kind = "" if not family else "_" + family.lower()
                signed, unsigned, suffix = f"int{kind}{width}_t", f"uint{kind}{width}_t", f"{family}{width}"
            for conversion in "diouxX":
                kind = signed if conversion in "di" else unsigned
                calls.append(f'    format_print("%" PRI{conversion}{suffix}, ({kind})0);')
            for conversion in "dioux":
                kind = signed if conversion in "di" else unsigned
                calls.append(f'    {{ {kind} value; format_scan("%" SCN{conversion}{suffix}, &value); }}')
    source = '#include <inttypes.h>\n'
    source += 'extern int format_print(const char*, ...) __attribute__((format(printf,1,2)));\n'
    source += 'extern int format_scan(const char*, ...) __attribute__((format(scanf,1,2)));\n'
    source += 'void check_macro_types(void) {\n' + '\n'.join(calls) + '\n}\n'
    compilers = [["x86_64-elf-gcc", "-ffreestanding", "-I" + str(ROOT / "include")],
                 [str(ROOT / "ports/zen/toolchain/alix-clang")]]
    for compiler in compilers:
        subprocess.run(compiler + ["-std=c11", "-fshort-wchar", "-Wformat=2", "-Werror", "-fsyntax-only", "-x", "c", "-"],
                       input=source, text=True, check=True)
    subprocess.run([str(ROOT / "ports/zen/toolchain/alix-clang++"), "-std=c++20", "-fsyntax-only", "-x", "c++", "-"],
                   input='#include <cinttypes>\nstatic_assert(sizeof(std::intmax_t)==8);\n', text=True, check=True)
    print(f"Native GCC/Clang inttypes macro and C++ header contracts passed ({len(calls)} formats per C compiler)")


if __name__ == "__main__":
    main()
