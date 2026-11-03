#!/usr/bin/env python3
"""Link the production Alix font scanner with configured FreeType and HarfBuzz."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import shlex
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ports/zen/rust"))
from gecko_fixture import FIXTURES, run
from build_freetype_library import build

ENGINE = ROOT / "ports/zen/upstream/firefox-159.0"
OBJ = ROOT / "ports/zen/upstream/obj-gecko-alix"
OUT = ROOT / "build/ports/zen/font-files-runtime"
OUT.mkdir(parents=True, exist_ok=True)
commands = json.loads((OBJ / "clangd/compile_commands.json").read_text())
support = []
sources = ["mfbt/Assertions.cpp", "mozglue/misc/Printf.cpp"]
sources += sorted({str(Path(item["file"]).relative_to(ENGINE)) for item in commands
                   if "/double-conversion/" in item["file"] and item["file"].endswith(".cc")})
for source in sources:
    entry = next(item for item in commands if item["file"].endswith("/" + source))
    output = OUT / (Path(source).stem + ".o")
    arguments = shlex.split(entry["command"])
    arguments[arguments.index("-o") + 1] = str(output)
    if "-MF" in arguments:
        arguments[arguments.index("-MF") + 1] = str(output.with_suffix(".o.d"))
    assert Path(arguments[-1]).name == Path(source).name
    subprocess.run(arguments, cwd=entry["directory"], check=True)
    support.append(str(output.relative_to(ROOT)))
build()
subprocess.run(["make", "-C", str(OBJ / "gfx/harfbuzz/src"), "-j2", "compile"], check=True)
subprocess.run(["make", "-C", str(OBJ / "memory/mozalloc"), "-j2", "compile"], check=True)
scanner = OBJ / "gfx/thebes/AlixFontFiles.o"
if not scanner.is_file():
    raise RuntimeError("the production Alix scanner has not been built")
harfbuzz = sorted((OBJ / "gfx/harfbuzz/src").glob("*.o"))
if not harfbuzz:
    raise RuntimeError("configured HarfBuzz objects missing")
test = OUT / "alix_font_files_test.o"
subprocess.run([str(ROOT / "ports/zen/toolchain/alix-clang++"), "-std=c++20", "-O2", "-g",
                "-I" + str(ENGINE / "gfx/thebes"), "-I" + str(ENGINE / "gfx/harfbuzz/src"),
                "-I" + str(ENGINE / "modules/freetype2/include"), "-c",
                str(ROOT / "tests/alix_font_files_test.cpp"), "-o", str(test)], check=True)
archive = OUT / "libfont-files-test.a"
subprocess.run(["x86_64-elf-ar", "crs", str(archive), str(test), str(scanner), *map(str, harfbuzz)], check=True)
FIXTURES["font-files"] = {
    "packages": ("libz-rs-sys",), "externs": ("libz_rs_sys",), "harness": True,
    "no_default_features": True,
    "dependencies": {"libz-rs-sys": {"version": "=0.6.3", "features": ["std", "rust-allocator", "custom-prefix"]}},
    "source": "tests/alix_font_files.rs", "elf": "alix_font_files_test.elf",
    "link_args": (str(archive.relative_to(ROOT)), "build/ports/zen/libalix-gecko-fonts.a",
                  "ports/zen/upstream/obj-gecko-alix/memory/mozalloc/Unified_cpp_memory_mozalloc0.o",
                  *support),
}
run("font-files")
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
(OUT / "native-link.json").write_text(json.dumps({
    "scope": "Production scanner and configured FreeType/HarfBuzz; guest execution separate",
    "objects": [{"path": str(p), "sha256": digest(p)} for p in
                [scanner, *harfbuzz, *[ROOT / p for p in support],
                 OBJ / "memory/mozalloc/Unified_cpp_memory_mozalloc0.o"]],
    "freetype_archive_sha256": digest(ROOT / "build/ports/zen/libalix-gecko-fonts.a"),
    "elf_sha256": digest(ROOT / "build/user/alix_font_files_test.elf"),
}, indent=2) + "\n")
