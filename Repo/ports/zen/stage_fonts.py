#!/usr/bin/env python3
"""Install only configured font resources, preserving other build outputs."""
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "ports/zen/upstream/firefox-159.0"
OBJ = ROOT / "ports/zen/upstream/obj-gecko-alix"
sys.path.insert(0, str(ENGINE / "python/mozbuild"))
from mozpack.copier import FileCopier
from mozpack.manifests import InstallManifest

manifest = InstallManifest(str(OBJ / "_build_manifests/install/dist_bin"))
configured = FileCopier()
manifest.populate_registry(configured)
fonts = FileCopier()
for name, file in configured:
    if name.startswith("fonts/"):
        fonts.add(name[len("fonts/"):], file)
expected = json.loads((ROOT / "ports/zen/fonts.json").read_text())
names = {Path(item["path"]).name for item in expected["fonts"]}
names.add("AlixFontLicenses.txt")
if set(fonts.paths()) != names:
    raise RuntimeError("configured native font files do not match the pinned manifest")
destination = OBJ / "dist/bin/fonts"
if destination.is_symlink():
    raise RuntimeError("font destination must be an owned build directory")
fonts.copy(str(destination), remove_unaccounted=False, remove_all_directory_symlinks=False)
for item in expected["fonts"]:
    data = (destination / Path(item["path"]).name).read_bytes()
    if hashlib.sha256(data).hexdigest() != item["sha256"]:
        raise RuntimeError("font asset differs from pinned source")
receipt = ROOT / "build/ports/zen/alix-font-assets.json"
receipt.write_text(json.dumps({"scope": "Configured native font assets; whole browser packaging pending",
    "directory": str(destination), "fonts": expected["fonts"], "licenses": str(destination / "AlixFontLicenses.txt")}, indent=2) + "\n")
print("Native font assets installed:", len(expected["fonts"]), "faces and license notices")
