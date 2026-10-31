#!/usr/bin/env python3
"""Cross-build upstream libc++/libc++abi for Alix; never use host archives."""
import argparse
import os
import shlex
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "ports/zen/upstream/llvm-project-22.1.8"
BUILD = ROOT / "ports/zen/upstream/libcxx-alix-build"
REVISION = "ca7933e47d3a3451d81e72ac174dcb5aa28b59d1"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configure-only", action="store_true")
    parser.add_argument("--smoke", action="store_true", help="link the native standard-library acceptance ELF")
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip()
    if revision != REVISION:
        raise RuntimeError("LLVM source does not match the pinned runtime revision")
    for patch in sorted(Path(__file__).with_name("patches").glob("*.patch")):
        applied = subprocess.run(["git", "apply", "--reverse", "--check", str(patch)],
                                 cwd=SOURCE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if applied.returncode:
            subprocess.run(["git", "apply", "--check", str(patch)], cwd=SOURCE, check=True)
            subprocess.run(["git", "apply", str(patch)], cwd=SOURCE, check=True)
    options = {
        "CMAKE_TOOLCHAIN_FILE": ROOT / "ports/zen/libcxx/alix-toolchain.cmake",
        "CMAKE_BUILD_TYPE": "Release", "CMAKE_INSTALL_PREFIX": BUILD / "install",
        "LLVM_ENABLE_RUNTIMES": "libcxx;libcxxabi", "LLVM_INCLUDE_TESTS": "OFF",
        "LLVM_ENABLE_PER_TARGET_RUNTIME_DIR": "OFF",
        "LIBCXX_ENABLE_SHARED": "OFF", "LIBCXX_ENABLE_STATIC": "ON",
        "LIBCXX_ENABLE_EXCEPTIONS": "OFF", "LIBCXX_ENABLE_RTTI": "ON",
        "LIBCXX_ENABLE_FILESYSTEM": "OFF", "LIBCXX_ENABLE_LOCALIZATION": "ON",
        "LIBCXX_ENABLE_UNICODE": "OFF", "LIBCXX_ENABLE_WIDE_CHARACTERS": "ON",
        "LIBCXX_ENABLE_RANDOM_DEVICE": "OFF", "LIBCXX_ENABLE_TIME_ZONE_DATABASE": "OFF",
        "LIBCXX_HAS_TERMINAL_AVAILABLE": "OFF",
        "LIBCXX_ENABLE_VENDOR_AVAILABILITY_ANNOTATIONS": "OFF",
        "LIBCXX_ENABLE_THREADS": "ON", "LIBCXX_HAS_EXTERNAL_THREAD_API": "ON",
        "LIBCXX_PSTL_BACKEND": "serial", "LIBCXX_INCLUDE_TESTS": "OFF",
        "LIBCXX_INCLUDE_BENCHMARKS": "OFF",
        "LIBCXX_HAS_PTHREAD_LIB": "OFF", "LIBCXX_HAS_RT_LIB": "OFF",
        "LIBCXXABI_ENABLE_SHARED": "OFF", "LIBCXXABI_ENABLE_STATIC": "ON",
        "LIBCXXABI_ENABLE_EXCEPTIONS": "OFF", "LIBCXXABI_USE_LLVM_UNWINDER": "OFF",
        "LIBCXXABI_ENABLE_THREADS": "ON", "LIBCXXABI_HAS_EXTERNAL_THREAD_API": "ON",
        "LIBCXXABI_INCLUDE_TESTS": "OFF", "LIBCXXABI_BAREMETAL": "ON",
        "LIBCXXABI_HAS_PTHREAD_LIB": "OFF",
    }
    subprocess.run(["cmake", "-G", "Ninja", "-S", str(SOURCE / "runtimes"), "-B", str(BUILD)] +
                   [f"-D{key}={value}" for key, value in options.items()], check=True)
    if not args.configure_only:
        subprocess.run(["cmake", "--build", str(BUILD), "--target", "cxx_static", "cxxabi_static", "-j", "8"], check=True)
        llvm = Path(os.environ.get("ALIX_LLVM_PREFIX", "/opt/homebrew/opt/llvm"))
        compiler = str(llvm / "bin/clang++")
        resource = subprocess.check_output([compiler, "--no-default-config", "-print-resource-dir"], text=True).strip()
        flags = ["--no-default-config", "--target=x86_64-unknown-none-elf", "-std=c++20", "-O2", "-g",
                 "-ffreestanding", "-fno-exceptions", "-fno-rtti", "-fuse-cxa-atexit", "-fno-pic",
                 "-fno-stack-protector", "-mno-red-zone", "-mcmodel=large", "-fshort-wchar",
                 "-ftls-model=local-exec", "-nostdinc", "-nostdinc++", "-D__ALIX__",
                 "-isystem", resource + "/include", "-isystem", str(ROOT / "include"),
                 "-I" + str(ROOT / "user/lib"), "-I" + str(ROOT / "ports/zen/libcxx")]
        support = BUILD / "alix-support"
        support.mkdir(exist_ok=True)
        inputs = [(ROOT / "ports/zen/libcxx/alix_threading.cpp", "threading.o",
                   ["-I" + str(BUILD / "include/c++/v1")]),
                  (ROOT / "user/lib/strtofloat.cpp", "strtofloat.o",
                   ["-I" + str(SOURCE / "libc"), "-DLIBC_NAMESPACE=alix_llvm_libc"]),
                  (ROOT / "user/lib/wcstofloat.c", "wcstofloat.o", [])]
        objects = []
        for source, output, extra in inputs:
            object_file = support / output
            selected_compiler, selected_flags = compiler, flags
            if source.suffix == ".c":
                selected_compiler = str(llvm / "bin/clang")
                selected_flags = [flag for flag in flags if flag not in
                                  ("-std=c++20", "-fno-exceptions", "-fno-rtti", "-fuse-cxa-atexit", "-nostdinc++")]
                selected_flags += ["-std=c11"]
            subprocess.run([selected_compiler] + selected_flags + extra +
                           ["-c", str(source), "-o", str(object_file)], check=True)
            objects.append(object_file)
        archive = BUILD / "lib/libalix-cxx-support.a"
        temporary_archive = archive.with_name(f".{archive.name}.{os.getpid()}.tmp")
        subprocess.run([str(llvm / "bin/llvm-ar"), "rcs", str(temporary_archive)] + list(map(str, objects)), check=True)
        temporary_archive.replace(archive)
        subprocess.run(["python3", str(ROOT / "ports/zen/libm/build.py")], check=True)
        if args.smoke:
            core = shlex.split(os.environ.get("ALIX_RUNTIME_OBJECTS", ""))
            if not core:
                raise RuntimeError("use make zen-cxx-runtime to supply Alix runtime objects")
            test_object = support / "libcxx_runtime_test.o"
            subprocess.run([compiler] + flags + ["-fhosted", "-I" + str(BUILD / "include/c++/v1"), "-c",
                           str(ROOT / "tests/libcxx_runtime_test.cpp"), "-o", str(test_object)], check=True)
            libgcc = subprocess.check_output(["x86_64-elf-gcc", "-print-libgcc-file-name"], text=True).strip()
            output = ROOT / "build/user/libcxx_runtime_test.elf"
            subprocess.run(["x86_64-elf-ld", "-nostdlib", "-T", str(ROOT / "user/lib/link.ld"),
                           "-o", str(output)] + [str(ROOT / obj) for obj in core] + [str(test_object),
                           "--start-group", str(BUILD / "lib/libc++.a"), str(BUILD / "lib/libc++abi.a"),
                           str(archive), str(ROOT / "ports/zen/upstream/libm-alix-build/lib/libalix-math.a"),
                           libgcc, "--end-group"], check=True)
            undefined = subprocess.check_output(["x86_64-elf-nm", "--undefined-only", str(output)], text=True)
            if undefined.strip(): raise RuntimeError("native C++ ELF has unresolved symbols: " + undefined)
            print(f"Native libc++ acceptance ELF linked: {output}")

if __name__ == "__main__":
    main()
