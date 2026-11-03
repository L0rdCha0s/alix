#!/usr/bin/env python3
"""Build Gecko's configured FreeType/libpng objects for native acceptance."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OBJ = ROOT / "ports/zen/upstream/obj-gecko-alix"
OUT = ROOT / "build/ports/zen"


def build():
    compilation = json.loads((OBJ / "clangd/compile_commands.json").read_text())
    objects = []
    for module in ("modules/freetype2", "media/libpng"):
        subprocess.run(["make", "-C", str(OBJ / module), "-j2", "compile"], check=True)
        selected = [entry for entry in compilation if "/" + module + "/" in entry["file"]]
        if not selected:
            raise RuntimeError("Gecko has no configured native objects for " + module)
        for entry in selected:
            obj = Path(entry["directory"]) / (Path(entry["file"]).stem + ".o")
            header = obj.read_bytes()[:20]
            if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != 62:
                raise RuntimeError("not a native x86-64 ELF object: " + str(obj))
            objects.append(obj)
    archive = OUT / "libalix-gecko-fonts.a"
    temporary = archive.with_name("." + archive.name + "." + str(os.getpid()))
    try:
        subprocess.run(["x86_64-elf-ar", "crs", str(temporary), *map(str, objects)], check=True)
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    (OUT / "native-freetype-objects.json").write_text(json.dumps({
        "scope": "Configured Gecko FreeType and libpng C objects; guest execution is separate",
        "archive": str(archive), "sha256": digest(archive),
        "objects": [{"path": str(path), "sha256": digest(path)} for path in objects],
    }, indent=2) + "\n")
    print("Native Gecko font archive:", archive, "objects:", len(objects))


if __name__ == "__main__":
    build()
