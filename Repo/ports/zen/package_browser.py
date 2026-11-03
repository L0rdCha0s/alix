#!/usr/bin/env python3
"""Stage the actual native browser, preserving runtime code, data and TLS."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def load_image(path):
    with path.open("rb") as stream:
        header = stream.read(64)
        if not header.startswith(b"\x7fELF"):
            return None
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            raise RuntimeError(f"unsupported ELF image: {path}")
        elf = struct.unpack("<16sHHIQQQIHHHHHH", header)
        if elf[1] not in (2, 3) or elf[2] != 62 or elf[9] != 56:
            raise RuntimeError(f"not a native x86-64 browser image: {path}")
        images = []
        for index in range(elf[10]):
            stream.seek(elf[5] + index * 56)
            kind, flags, offset, address, _, filesz, memsz, alignment = struct.unpack("<IIQQQQQQ", stream.read(56))
            if kind == 3:
                raise RuntimeError(f"host startup interpreter in browser image: {path}")
            if kind not in (1, 7):
                continue
            stream.seek(offset)
            digest = hashlib.sha256()
            remaining = filesz
            while remaining:
                data = stream.read(min(remaining, 1024 * 1024))
                if not data:
                    raise RuntimeError(f"truncated native image: {path}")
                if kind == 1 and offset == 0 and remaining == filesz:
                    # strip updates the non-runtime section-table offset,
                    # count and string-table index in the mapped ELF header.
                    # Program headers and all other load/TLS bytes must match.
                    data = bytearray(data)
                    data[40:48] = bytes(8)
                    data[60:64] = bytes(4)
                digest.update(data)
                remaining -= len(data)
            images.append([kind, flags, address, filesz, memsz, alignment, digest.hexdigest()])
        return {"type": elf[1], "entry": elf[4], "images": images}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entry", default="firefox")
    parser.add_argument("--source", type=Path, help="Use an already staged browser directory")
    parser.add_argument("--objdir", type=Path, default=ROOT / "ports/zen/upstream/obj-gecko-alix")
    parser.add_argument("--output", type=Path, default=ROOT / "build/ports/zen/gecko-native")
    args = parser.parse_args()
    objdir = args.objdir.resolve()
    source = args.source.resolve() if args.source else objdir / "dist/bin"
    if Path(args.entry).name != args.entry or not (source / args.entry).is_file():
        raise RuntimeError("the actual browser executable must exist before packaging")
    archive = args.output.with_suffix(".zip")
    for output in (args.output, archive):
        if output.exists() or output.is_symlink():
            raise RuntimeError(f"existing browser output preserved: {output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".browser-stage-", dir=args.output.parent) as temporary:
        original = source
        if not args.source:
            configuration = (objdir / "config/autoconf.mk").read_text().splitlines()
            python = next(line.split("=", 1)[1].strip() for line in configuration
                          if line.startswith("PYTHON3 = "))
            source = Path(temporary).resolve() / "omni"
            environment = dict(os.environ)
            environment["NO_PKG_FILES"] = (environment.get("NO_PKG_FILES", "") +
                                           " gmp-fake/** gmp-fakeopenh264/**" +
                                           (" firefox firefox-bin" if args.entry == "zen" else "")).strip()
            installer = ROOT / "ports/zen/upstream/firefox-159.0/toolkit/mozapps/installer/packager.py"
            subprocess.run([python, str(installer), "--format", "omni", "dist", str(source)],
                           cwd=objdir, env=environment, check=True)
        stage = Path(temporary) / "browser"
        # Mozilla's FasterMake tree uses host source symlinks. Materialize the
        # bytes so the guest never depends on a host checkout path.
        shutil.copytree(source, stage, symlinks=False,
                        ignore=shutil.ignore_patterns("gmp-fake", "gmp-fakeopenh264",
                                                     "alix-browser-manifest.json"))
        native = []
        files = []
        for path in sorted(stage.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(stage).as_posix()
            image = load_image(path)
            if image:
                original_path = original / relative
                if not original_path.is_file() or load_image(original_path) != image:
                    raise RuntimeError(f"packaging changed browser load/TLS bytes: {relative}")
                before = original_path.stat().st_size
                stripped = path.with_name(path.name + ".stripped")
                subprocess.run(["x86_64-elf-strip", "--strip-debug", "-o", str(stripped), str(path)], check=True)
                if load_image(stripped) != image:
                    raise RuntimeError(f"stripping changed browser load/TLS bytes: {relative}")
                stripped.chmod(path.stat().st_mode & 0o777)
                stripped.replace(path)
                native.append({"path": relative, "source_bytes": before, "bytes": path.stat().st_size, "image": image})
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            files.append({"path": relative, "bytes": path.stat().st_size, "sha256": digest})
        manifest = {"source": str(original), "format": "staged" if args.source else "omni",
                    "entry": args.entry, "native_images": native,
                    "files": files, "updater_present": (stage / "updater").is_file()}
        (stage / "alix-browser-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        shutil.move(stage, args.output)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as package:
        for path in sorted(args.output.rglob("*")):
            if path.is_file():
                package.write(path, path.relative_to(args.output))
    print(f"Native browser staged: {args.output}; {len(files)} files, {len(native)} ELF images")
    print(f"Browser archive: {archive} ({archive.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
