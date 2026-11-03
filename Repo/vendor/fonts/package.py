#!/usr/bin/env python3
"""Build the offline system-font bundle; optionally restore pinned upstream files."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request
import zipfile

DIRECTORY = Path(__file__).resolve().parent


def checked_assets(directory=DIRECTORY, fetch=False):
    manifest_bytes = (directory / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest["format_version"] != 1:
        raise ValueError("unsupported font manifest version")
    assets = {"manifest.json": manifest_bytes}
    for entry in manifest["assets"]:
        name = entry["file"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or name in assets:
            raise ValueError(f"invalid or duplicate font asset: {name}")
        path = directory / name
        data = path.read_bytes() if path.exists() else b""
        if fetch and hashlib.sha256(data).hexdigest() != entry["sha256"]:
            source = manifest["sources"][entry["source"]]
            repository = source["repository"].removeprefix("https://github.com/")
            prefix = f"https://raw.githubusercontent.com/{repository}/{source['revision']}/"
            if not entry["url"].startswith(prefix):
                raise ValueError(f"font URL is not pinned to its source revision: {name}")
            request = urllib.request.Request(entry["url"], headers={"User-Agent": "Alix-font-packaging"})
            with urllib.request.urlopen(request, timeout=120) as response:
                data = response.read()
        if len(data) != entry["size"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"font asset is missing or changed: {path}; run 'make fonts-fetch' to restore")
        if "family" in entry and data[:4] not in (b"\x00\x01\x00\x00", b"OTTO", b"ttcf"):
            raise ValueError(f"invalid OpenType font signature: {name}")
        if fetch and (not path.exists() or path.read_bytes() != data):
            temporary = path.with_name(path.name + ".tmp")
            try:
                temporary.write_bytes(data)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        assets[name] = data
    return manifest, assets


def build(output, directory=DIRECTORY, fetch=False):
    manifest, assets = checked_assets(directory, fetch)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=output.parent, prefix=output.name + ".", delete=False) as handle:
        temporary = Path(handle.name)
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(assets.items()):
                info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data, compresslevel=9)
        temporary.chmod(0o644)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    fonts = sum("family" in entry for entry in manifest["assets"])
    print(f"System fonts: {fonts} font files, {sum(map(len, assets.values()))} installed bytes, "
          f"{output.stat().st_size} ZIP bytes -> {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fetch", action="store_true", help="restore assets from pinned upstream URLs")
    parser.add_argument("--list", action="store_true", help="list manifest filenames for Make dependencies")
    args = parser.parse_args()
    if args.list:
        print(" ".join(entry["file"] for entry in json.loads((DIRECTORY / "manifest.json").read_bytes())["assets"]))
    elif args.output is None:
        parser.error("--output is required when building the font bundle")
    else:
        build(args.output, fetch=args.fetch)
