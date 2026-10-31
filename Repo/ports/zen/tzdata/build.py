#!/usr/bin/env python3
"""Fetch/build pinned official IANA data and emit an immutable native install bundle."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import struct
import subprocess
import tarfile
import tempfile
import urllib.request
from zoneinfo import ZoneInfo

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = json.loads((HERE / "upstream.json").read_text())
DEFAULT_CACHE = ROOT / "ports/zen/upstream" / ("tzdata-" + PIN["release"])


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    return (name and not path.is_absolute() and str(path) == name and
            all(part not in ("", ".", "..") and all(c.isascii() and (c.isalnum() or c in "_+.-") for c in part)
                for part in name.split("/")))


def write_preserving(path, data):
    for parent in path.parents:
        if parent.is_symlink():
            raise RuntimeError(f"preserving symlinked parent {parent}")
    if path.is_symlink():
        raise RuntimeError(f"preserving symlink at {path}")
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            raise RuntimeError(f"preserving modified existing file {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def sources(cache, fetch):
    expected = {}
    for archive in PIN["archives"]:
        path = cache / "downloads" / archive["file"]
        if not path.exists():
            if not fetch:
                raise RuntimeError(f"missing pinned source {path}; rerun with --fetch")
            path.parent.mkdir(parents=True, exist_ok=True)
            request = urllib.request.Request(archive["url"], headers={"User-Agent": "Alix-native-tzdata-port/1"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read(archive["bytes"] + 1)
            if len(data) != archive["bytes"] or digest(data) != archive["sha256"]:
                raise RuntimeError("download does not match pinned source: " + archive["file"])
            write_preserving(path, data)
        data = path.read_bytes()
        if len(data) != archive["bytes"] or digest(data) != archive["sha256"]:
            raise RuntimeError("cached archive differs from pin: " + str(path))
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as source:
            for member in source.getmembers():
                if not member.isfile() or not safe_name(member.name):
                    raise RuntimeError("unsupported source archive member: " + member.name)
                content = source.extractfile(member).read()
                if member.name in expected and expected[member.name] != content:
                    raise RuntimeError("conflicting source archives: " + member.name)
                expected[member.name] = content
    if expected.get("version", b"").strip().decode() != PIN["release"]:
        raise RuntimeError("source version does not match pin")
    source = cache / "source"
    if source.exists():
        for path in source.rglob("*"):
            if path.is_symlink() or (path.is_file() and path.relative_to(source).as_posix() not in expected):
                raise RuntimeError("preserving unexpected source entry: " + str(path))
    for name, data in expected.items():
        write_preserving(source / name, data)
    return source, expected


def validate_tzif(data, name):
    def header(offset, width):
        if data[offset:offset+4] != b"TZif" or data[offset+4:offset+5] not in (b"2", b"3", b"4"):
            raise RuntimeError("expected ordinary TZif v2+: " + name)
        ut, standard, leaps, transitions, types, names = struct.unpack_from(">6I", data, offset+20)
        if leaps or not types or types > 256 or not names or ut not in (0, types) or standard not in (0, types):
            raise RuntimeError("invalid/non-POSIX TZif profile: " + name)
        return offset + 44 + transitions * (width + 1) + types * 6 + names + standard + ut
    second = header(0, 4)
    end = header(second, 8)
    footer = data[end:]
    if len(data) > 1024 * 1024 or len(footer) < 3 or footer[:1] != b"\n" or footer[-1:] != b"\n":
        raise RuntimeError("TZif footer missing or native size exceeded: " + name)
    ZoneInfo.from_file(io.BytesIO(data), key=name)


def build(cache, source, expected):
    working = cache / "zic-build-pinned"
    for name, data in expected.items():
        write_preserving(working / name, data)
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "TZ": "UTC"})
    # Recompile cached host tools, but never let upstream's Git-based version
    # rule inspect the enclosing Alix checkout and append an unrelated -dirty.
    subprocess.run(["make", "-s", "-B", "-o", "version", "-C", str(working), "zic", "tzdata.zi",
                    "VERSION="+PIN["release"], "DATAFORM=main", "REDO=posix_only", "BACKWARD=backward"],
                   env=env, check=True)
    version = subprocess.check_output([str(working / "zic"), "--version"], env=env, text=True).strip()
    if version != "zic (tzcode) " + PIN["release"]:
        raise RuntimeError("host zic version does not match pinned sources")
    output = cache / "packages"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".zic-output-", dir=cache) as temporary:
        stage = Path(temporary)
        subprocess.run([str(working / "zic"), "-b", "fat", "-d", str(stage), str(working / "tzdata.zi")], env=env, check=True)
        entries = {}
        for path in sorted(stage.rglob("*")):
            if path.is_dir():
                continue
            relative = path.relative_to(stage).as_posix()
            if not safe_name(relative) or not path.resolve().is_relative_to(stage.resolve()) or not path.is_file():
                raise RuntimeError("unsafe/nonregular zic output: " + relative)
            data = path.read_bytes()
            validate_tzif(data, relative)
            entries["zoneinfo/" + relative] = data
        aliases = {}
        required = set()
        for line in (working / "tzdata.zi").read_text().splitlines():
            fields = line.split()
            if fields and fields[0] == "Z":
                required.add(fields[1])
            elif fields and fields[0] == "L":
                aliases[fields[2]] = fields[1]
                required.add(fields[2])
        if set(name.removeprefix("zoneinfo/") for name in entries) != required:
            raise RuntimeError("compiled zone and alias inventory differs from official source")
        for alias, target in aliases.items():
            if entries["zoneinfo/" + alias] != entries["zoneinfo/" + target]:
                raise RuntimeError("alias bytes differ from target: " + alias)
        for name in ("LICENSE", "version", "zone.tab", "zone1970.tab", "zonenow.tab", "iso3166.tab"):
            entries["metadata/" + name] = (source / name).read_bytes()
        entries["metadata/tzdata.zi"] = (working / "tzdata.zi").read_bytes()
        manifest = {
            "format": "alix-iana-tzif-package-v1", "release": PIN["release"], "zic": version,
            "source_archives": PIN["archives"], "profile": PIN["build_profile"],
            "aliases": aliases,
            "files": [{"path": name, "bytes": len(data), "sha256": digest(data)} for name, data in sorted(entries.items())],
        }
        manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        manifest_hash = digest(manifest_bytes)
        release_id = "iana-" + PIN["release"] + "-" + manifest_hash[:16]
        entries["manifest.json"] = manifest_bytes
        package = output / release_id
        for name, data in entries.items():
            write_preserving(package / name, data)
        bundle = bytearray(struct.pack("<8sII", b"ALIXTZP1", 1, len(entries)))
        for name, data in sorted(entries.items()):
            path = name.encode("ascii")
            bundle += struct.pack("<II32s", len(path), len(data), bytes.fromhex(digest(data))) + path + data
        bundle_name = release_id + ".bundle"
        write_preserving(output / bundle_name, bytes(bundle))
        installer_config = (
            "/* Generated from the pinned, verified complete package. */\n"
            f'#define TZ_PACKAGE_RELEASE "{PIN["release"]}"\n'
            f'#define TZ_PACKAGE_ID "{release_id}"\n'
            f'#define TZ_PACKAGE_ROOT "/usr/share/zoneinfo/.alix-releases/{release_id}"\n'
            f'#define TZ_PACKAGE_SHA256 "{digest(bundle)}"\n'
            f'#define TZ_PACKAGE_SIZE {len(bundle)}u\n'
            f'#define TZ_PACKAGE_ENTRIES {len(entries)}u\n'
        ).encode()
        write_preserving(output / (release_id + ".h"), installer_config)
        receipt = {"release": PIN["release"], "id": release_id, "manifest_sha256": manifest_hash,
                   "bundle": str((output / bundle_name).resolve()), "bundle_sha256": digest(bundle),
                   "bundle_bytes": len(bundle), "entries": len(entries), "zones_and_aliases": len(required),
                   "aliases": len(aliases), "installer_config": str((output / (release_id + ".h")).resolve()),
                   "package_directory": str(package.resolve())}
        write_preserving(output / (release_id + ".json"), (json.dumps(receipt, indent=2) + "\n").encode())
        print(json.dumps(receipt, indent=2))
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    args = parser.parse_args()
    cache = args.cache.resolve()
    if cache.is_relative_to((ROOT / "build").resolve()):
        parser.error("keep IANA source and build caches outside QEMU's FAT-backed build directory")
    cache.mkdir(parents=True, exist_ok=True)
    source, expected = sources(cache, args.fetch)
    build(cache, source, expected)


if __name__ == "__main__":
    main()
