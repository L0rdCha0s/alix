#!/usr/bin/env python3
"""Build actual native libc++ acceptance fixtures with the Alix runtime."""
import json
import argparse
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--wide", action="store_true")
    modes.add_argument("--wide-float", action="store_true")
    modes.add_argument("--nearbyint", action="store_true")
    modes.add_argument("--math-support", action="store_true")
    modes.add_argument("--random-device", action="store_true")
    args = parser.parse_args()
    objects = shlex.split(os.environ.get("ALIX_RUNTIME_OBJECTS", ""))
    if not objects:
        raise RuntimeError("use make zen-cxx-stream-test to supply native runtime objects")
    state = ROOT / "ports/zen/upstream/alix-toolchain"
    state.mkdir(parents=True, exist_ok=True)
    manifest = state / "runtime-objects.json"
    temporary = manifest.with_name(f".{manifest.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps([str((ROOT / value).resolve()) for value in objects], indent=2) + "\n")
    temporary.replace(manifest)
    env = os.environ.copy()
    env["ALIX_RUNTIME_MANIFEST"] = str(manifest)
    if args.random_device:
        output = ROOT / "build/user/random_device_test.elf"
        sources = [ROOT / "tests/random_device_test.cpp"]
        compiler, standard = "alix-clang++", "-std=c++20"
        macros = subprocess.check_output([str(ROOT / "ports/zen/toolchain" / compiler),
            "-std=c++20", "-dM", "-E", "-x", "c++", "-"], input="#include <random>\n", env=env, text=True)
        if "#define _LIBCPP_HAS_RANDOM_DEVICE 1" not in macros or "#define _LIBCPP_USING_GETENTROPY" not in macros:
            raise RuntimeError("rebuild make zen-cxx-runtime with native random_device/getentropy enabled")
    elif args.wide_float or args.nearbyint or args.math_support:
        name = "math_support_test" if args.math_support else ("math_nearbyint_test" if args.nearbyint else "wchar_float_test")
        output = ROOT / f"build/user/{name}.elf"
        sources = [ROOT / f"tests/{name}.c"]
        compiler, standard = "alix-clang", "-std=c11"
    else:
        output = ROOT / ("build/user/cxx_wide_test.elf" if args.wide else "build/user/cxx_stream_test.elf")
        sources = [ROOT / "tests/cxx_wide_test.cpp", ROOT / "tests/cxx_wide_backend_probe.cpp"] if args.wide else [ROOT / "tests/cxx_stream_test.cpp"]
        compiler, standard = "alix-clang++", "-std=c++20"
    subprocess.run([str(ROOT / "ports/zen/toolchain" / compiler), standard, "-O2",
                    *(["-frounding-math", "-fno-builtin"] if args.nearbyint or args.math_support else []),
                    *map(str, sources), "-o", str(output)], env=env, check=True)
    if subprocess.check_output(["x86_64-elf-nm", "--undefined-only", str(output)], text=True).strip():
        raise RuntimeError("native C++ stream acceptance ELF contains unresolved symbols")
    label = "libc++ random-device" if args.random_device else "C++ stream and C/POSIX locale"
    print(f"Native {label} fixture linked: {output}")
    print("The fixture must run in Alix before claiming its behavior is verified.")


if __name__ == "__main__":
    main()
