"""Clang driver for genuine native Alix ELF compilation and static linking."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
RUNTIME = ROOT / "ports/zen/upstream/libcxx-alix-build"


def main(cxx=False):
    llvm = Path(os.environ.get("ALIX_LLVM_PREFIX", "/opt/homebrew/opt/llvm"))
    compiler = llvm / "bin" / ("clang++" if cxx else "clang")
    gcc = shutil.which("x86_64-elf-gcc")
    if not gcc:
        raise RuntimeError("x86_64-elf-gcc is required as Clang's native ELF link driver")
    resource = subprocess.check_output([str(compiler), "--no-default-config", "-print-resource-dir"], text=True).strip()
    flags = ["--no-default-config", "--target=x86_64-unknown-alix", "-ccc-gcc-name", Path(gcc).name, "-D__ALIX__",
             "-fhosted", "-fno-builtin", "-frounding-math", "-ffp-contract=off", "-fno-pic", "-fno-stack-protector",
             "-mno-red-zone", "-mcmodel=large", "-fshort-wchar", "-ftls-model=local-exec",
             "-nostdinc"]
    if cxx:
        # Explicit consumer -I directories (notably Mozilla's visibility
        # wrappers) precede system headers. libc++ must still precede the C
        # sysroot for include_next and its C-header wrappers to work.
        flags += ["-nostdinc++", "-fno-exceptions", "-isystem", str(RUNTIME / "include/c++/v1"),
                  "-I" + str(ROOT / "ports/zen/libcxx")]
    flags += ["-isystem", resource + "/include", "-isystem", str(ROOT / "include"),
              "-I" + str(ROOT / "user/lib")]
    arguments = sys.argv[1:]
    no_link = (not arguments or any(arg in ("-c", "-S", "-E", "-fsyntax-only", "-M", "-MM")
                                   for arg in arguments) or
               any(arg.startswith(("-print-", "--print-", "-dump", "--version")) for arg in arguments) or
               arguments == ["-v"])
    if not no_link:
        if "-shared" in arguments:
            raise RuntimeError("Alix shared-object loading is not implemented; this gate builds static SpiderMonkey")
        manifest = Path(os.environ.get("ALIX_RUNTIME_MANIFEST", str(ROOT / "ports/zen/upstream/alix-toolchain/runtime-objects.json")))
        objects = json.loads(manifest.read_text())
        if not objects or not any(Path(obj).name == "crt0.o" for obj in objects):
            raise RuntimeError("native Alix startup objects are missing")
        names = [Path(obj).name for obj in objects]
        if ("syscall.o" in names or names.count("syscall-owned.o") != 1 or names.count("fcntl.o") != 1 or
                "libc.o" in names or names.count("libc-upstream.o") != 1):
            raise RuntimeError("upstream links require the owned-FD runtime; use the current make zen-* target")
        for obj in objects:
            path = Path(obj)
            header = path.read_bytes()[:20]
            if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 62:
                raise RuntimeError(f"runtime object is not native x86-64 ELF: {path}")
            if "/web/" in path.as_posix() or "html_view" in path.name:
                raise RuntimeError("legacy Alix browser engine must not enter the upstream link")
        linker = shutil.which("x86_64-elf-ld")
        if not linker:
            raise RuntimeError("x86_64-elf-ld is required for the native Alix link")
        libgcc = subprocess.check_output(["x86_64-elf-gcc", "-print-libgcc-file-name"], text=True).strip()
        libraries = [RUNTIME / "lib/libc++.a", RUNTIME / "lib/libc++abi.a", RUNTIME / "lib/libalix-cxx-support.a",
                     ROOT / "ports/zen/upstream/libm-alix-build/lib/libalix-math.a",
                     ROOT / "build/user/lib/libalix-ssp.a"]
        for library in libraries:
            if not library.is_file():
                raise RuntimeError(f"native runtime archive is missing: {library}")
        # Alix's complete math implementations are already in its runtime
        # objects and grouped native math archive below. Resolve the customary
        # -lm request there, after object inputs, instead of searching a host
        # sysroot or pulling a second early copy of those same definitions.
        arguments = [argument for argument in arguments if argument != "-lm"]
        arguments += ["-nostdlib", "-static",
                      "-Wl,-T," + str(ROOT / "user/lib/link.ld"), "-Wl,-z,max-page-size=0x1000",
                      "-Wl,--start-group", "-x", "none"] + objects + list(map(str, libraries)) + [libgcc, "-Wl,--end-group"]
    os.execv(compiler, [str(compiler)] + flags + arguments)
