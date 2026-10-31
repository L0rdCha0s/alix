#!/usr/bin/env python3
"""Prepare pinned Zen sources and probe Alix's native port prerequisites.

This does not build Zen for the host and does not claim an Alix browser exists.
Fetching never runs upstream scripts, npm lifecycle hooks, or mach bootstrap.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("upstream.json")
DEFAULT_SOURCE = Path(__file__).parent / "upstream/desktop"


def run(*args, cwd=None):
    result = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, args))}: {result.stderr.strip()}")
    return result.stdout.strip()


def load_manifest():
    manifest = json.loads(MANIFEST.read_text())
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["revision"]):
        raise ValueError("upstream revision must be a full Git commit ID")
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["firefox_revision"]):
        raise ValueError("Firefox revision must be a full Git commit ID")
    if not re.fullmatch(r"[0-9a-f]{128}", manifest["firefox_source_sha512"]):
        raise ValueError("Firefox source checksum must be a full SHA-512 digest")
    return manifest


def verify_source(source, manifest):
    # Do not accidentally operate on Alix's enclosing repository.
    if not (source / ".git").is_dir():
        raise RuntimeError(f"{source} is not a dedicated Zen Git checkout")
    if Path(run("git", "rev-parse", "--show-toplevel", cwd=source)).resolve() != source.resolve():
        raise RuntimeError("source directory is not the checkout root")
    if run("git", "remote", "get-url", "origin", cwd=source) != manifest["repository"]:
        raise RuntimeError("source origin does not match upstream.json")
    if run("git", "rev-parse", "HEAD", cwd=source) != manifest["revision"]:
        raise RuntimeError("source revision does not match upstream.json; checkout left untouched")
    # Port work must never be discarded or silently treated as pristine upstream.
    if run("git", "status", "--porcelain", "--untracked-files=all", cwd=source):
        raise RuntimeError("source checkout has local changes; left untouched")
    surfer = json.loads((source / "surfer.json").read_text())
    if surfer["version"]["version"] != manifest["firefox_version"]:
        raise RuntimeError("upstream Firefox version differs from the recorded base")
    if surfer["brands"]["release"]["release"]["displayVersion"] != manifest["release"]:
        raise RuntimeError("upstream Zen release differs from the recorded release")
    if not (source / "LICENSE").is_file():
        raise RuntimeError("upstream license is missing")


def fetch_source(source, manifest):
    if source.exists() or source.is_symlink():
        verify_source(source, manifest)
        print(f"Pinned Zen source already present: {source}")
        return
    source.parent.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(source.parent).free < 1024 ** 3:
        raise RuntimeError("source checkout requires at least 1 GiB free; no download started")
    # Publish only after the pin and release metadata have been checked. Never
    # reset, clean, or replace a previous checkout (including a partial one).
    with tempfile.TemporaryDirectory(prefix=".zen-fetch-", dir=source.parent) as staging:
        checkout = Path(staging) / "desktop"
        run("git", "init", "--quiet", str(checkout))
        run("git", "remote", "add", "origin", manifest["repository"], cwd=checkout)
        print(f"Fetching Zen {manifest['release']} at {manifest['revision']}", flush=True)
        run("git", "fetch", "--depth=1", "--no-tags", "origin", manifest["revision"], cwd=checkout)
        run("git", "-c", "advice.detachedHead=false", "checkout", "--detach", "FETCH_HEAD", cwd=checkout)
        verify_source(checkout, manifest)
        # rename() can replace an empty directory, so refuse a concurrent arrival.
        if source.exists() or source.is_symlink():
            raise RuntimeError("destination appeared during fetch; left untouched")
        checkout.rename(source)
    print(f"Verified Zen source: {source}")
    print("This command prepares only the Zen overlay; use zen-fetch-engine for Firefox sources.")


def digest_stream(stream, algorithm):
    digest = hashlib.new(algorithm)
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def verify_engine_archive(archive, manifest):
    if archive.is_symlink() or not archive.is_file():
        raise RuntimeError(f"engine archive must be a regular file: {archive}")
    with archive.open("rb") as stream:
        actual = digest_stream(stream, "sha512")
    if actual != manifest["firefox_source_sha512"]:
        raise RuntimeError("Firefox archive SHA-512 mismatch; archive and existing sources left untouched")


def download_engine_archive(archive, manifest):
    if archive.exists() or archive.is_symlink():
        verify_engine_archive(archive, manifest)
        return
    # A manually started or interrupted download belongs to its caller. Do not
    # resume, overwrite, rename, or remove it behind that caller's back.
    partial = archive.with_suffix(archive.suffix + ".partial")
    if partial.exists() or partial.is_symlink():
        raise RuntimeError("Firefox archive has an existing .partial download; left untouched")
    archive.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".firefox-download-", dir=archive.parent) as temporary:
        pending = Path(temporary) / archive.name
        print(f"Downloading Firefox {manifest['firefox_version']} sources", flush=True)
        request = urllib.request.Request(manifest["firefox_source_url"],
                                         headers={"User-Agent": "Alix-Zen-source-preparation/1"})
        with urllib.request.urlopen(request, timeout=60) as response, pending.open("xb") as output:
            shutil.copyfileobj(response, output, length=1024 * 1024)
        verify_engine_archive(pending, manifest)
        # Link publication cannot overwrite a destination created concurrently.
        os.link(pending, archive)
    print(f"Verified Firefox archive: {archive}")


def engine_member_path(member, source_root):
    name = PurePosixPath(member.name)
    # Mozilla's release tarball begins with a container-root directory entry,
    # followed by firefox-VERSION/... entries. It is not part of the source
    # tree, and skipping it avoids changing the staging directory's metadata.
    if name == PurePosixPath(".") and member.isdir():
        return None
    if (name.is_absolute() or ".." in name.parts or not name.parts
            or name.parts[0] != source_root):
        raise RuntimeError(f"unsafe Firefox archive member: {member.name}")
    if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
        raise RuntimeError(f"unsupported Firefox archive member: {member.name}")
    if member.issym() or member.islnk():
        link = PurePosixPath(member.linkname)
        target = (name.parent / link) if member.issym() else link
        normalized = PurePosixPath(posixpath.normpath(str(target)))
        if link.is_absolute() or not normalized.parts or normalized.parts[0] != source_root:
            raise RuntimeError(f"unsafe Firefox archive link: {member.name}")
        # Python 3.14's data filter normalizes link strings. Do it consistently
        # here so extraction and later verification agree on older Pythons too.
        member.linkname = posixpath.normpath(member.linkname)
    return Path(*name.parts[1:])


def verify_engine_metadata(source, manifest):
    for required in ("LICENSE", "mach", "build/moz.configure/init.configure"):
        if not (source / required).is_file():
            raise RuntimeError(f"Firefox source is missing {required}")
    version = (source / "browser/config/version.txt").read_text().strip()
    if version != manifest["firefox_version"]:
        raise RuntimeError("Firefox archive release metadata differs from upstream.json")


def verify_engine_tree(source, archive, manifest):
    """Compare against the trusted archive, not an editable provenance marker."""
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError("existing Firefox source is not a regular directory; left untouched")
    expected = set()
    seen = set()
    source_root = "firefox-" + manifest["firefox_version"]
    root = source.resolve()
    with tarfile.open(archive, "r:xz") as package:
        for member in package:
            relative = engine_member_path(member, source_root)
            if relative is None or relative == Path("."):
                continue
            if relative in seen:
                raise RuntimeError(f"duplicate Firefox archive member: {member.name}")
            seen.add(relative)
            expected.add(relative)
            expected.update(parent for parent in relative.parents if parent != Path("."))
            path = source / relative
            if not path.parent.resolve().is_relative_to(root):
                raise RuntimeError(f"Firefox source path escapes its root: {relative}; left untouched")
            valid = False
            if member.isdir():
                valid = path.is_dir() and not path.is_symlink()
            elif member.issym():
                valid = path.is_symlink() and os.readlink(path) == member.linkname
            elif path.is_file() and not path.is_symlink():
                with package.extractfile(member) as original, path.open("rb") as current:
                    valid = digest_stream(original, "sha256") == digest_stream(current, "sha256")
                valid = valid and bool(path.stat().st_mode & 0o100) == bool(member.mode & 0o100)
            if not valid:
                raise RuntimeError(f"Firefox source differs from verified archive: {relative}; left untouched")
    actual = {path.relative_to(source) for path in source.rglob("*")}
    if actual != expected:
        difference = sorted(map(str, actual ^ expected))[:3]
        raise RuntimeError(f"Firefox source has added/missing paths: {difference}; left untouched")
    verify_engine_metadata(source, manifest)


def fetch_engine(source, archive, manifest):
    for path in (source, archive):
        if path.resolve().is_relative_to((ROOT / "build").resolve()):
            raise RuntimeError("Firefox sources and archive must be outside QEMU's build/ FAT disk")
    source.parent.mkdir(parents=True, exist_ok=True)
    download_engine_archive(archive, manifest)
    if source.exists() or source.is_symlink():
        print("Verifying existing Firefox source against the pinned archive (may take a few minutes)", flush=True)
        verify_engine_tree(source, archive, manifest)
        print(f"Verified existing Firefox source: {source}")
        return
    if shutil.disk_usage(source.parent).free < 8 * 1024 ** 3:
        raise RuntimeError("Firefox source extraction requires at least 8 GiB free; no extraction started")
    if not hasattr(tarfile, "data_filter"):
        raise RuntimeError("safe Firefox extraction requires Python with tarfile.data_filter")
    source_root = "firefox-" + manifest["firefox_version"]
    print(f"Extracting verified Firefox {manifest['firefox_version']} sources", flush=True)
    with tempfile.TemporaryDirectory(prefix=".firefox-extract-", dir=source.parent) as temporary:
        staging = Path(temporary)
        seen = set()
        with tarfile.open(archive, "r:xz") as package:
            for member in package:
                relative = engine_member_path(member, source_root)
                if relative is None:
                    continue
                if relative in seen:
                    raise RuntimeError(f"duplicate Firefox archive member: {member.name}")
                seen.add(relative)
                package.extract(member, path=staging, filter="data")
        extracted = staging / source_root
        verify_engine_metadata(extracted, manifest)
        if source.exists() or source.is_symlink():
            raise RuntimeError("Firefox destination appeared during extraction; left untouched")
        extracted.rename(source)
    print(f"Verified Firefox source extracted: {source}")
    print("Source preparation only: no upstream scripts ran and no Alix browser was built.")


PROBES = {
    "alix_cxx_headers": '#include "libc.h"\n#include "usyscall.h"\n#include "atk_user.h"\n',
    "posix_threads": '#include <pthread.h>\nvoid probe() { pthread_t t; pthread_join(t, nullptr); }\n',
    "virtual_memory": '#include <sys/mman.h>\nvoid probe() { mprotect(nullptr, 4096, PROT_READ); munmap(nullptr, 4096); mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0); }\n',
    "dynamic_loading": '#include <dlfcn.h>\nvoid probe() { dlopen("libxul.so", RTLD_NOW); }\n',
    "posix_poll": '#include <poll.h>\nvoid probe() { poll(nullptr, 0, 0); }\n',
    "cxx_standard_library": '#include <atomic>\n#include <type_traits>\nstd::atomic<unsigned> value{0};\n',
}


def preflight(source, manifest):
    print(f"Zen {manifest['release']} / Firefox {manifest['firefox_version']}")
    print("Status: native Alix port is incomplete; no Zen executable is produced.")
    try:
        verify_source(source, manifest)
        print("PASS: pinned Zen checkout and release metadata")
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"MISSING: source preparation: {error}")
    existing = source.parent
    while not existing.exists():
        existing = existing.parent
    free_gib = shutil.disk_usage(existing).free / 1024 ** 3
    label = "PASS" if free_gib >= manifest["build_space_gib"] else "MISSING"
    print(f"{label}: build disk space: {free_gib:.1f} GiB free; upstream minimum {manifest['build_space_gib']} GiB")
    for name in ("git", "python3", "node", "npm", "cargo", "rustc", "clang", "sccache"):
        found = shutil.which(name)
        print(f"{'FOUND' if found else 'MISSING'}: host tool {name}: {found or 'not on PATH'}")
    compiler = os.environ.get("ALIX_CXX", "x86_64-elf-g++")
    output = ROOT / "build/ports/zen/preflight"
    output.mkdir(parents=True, exist_ok=True)
    if shutil.which(compiler):
        target = run(compiler, "-dumpmachine")
        if target not in ("x86_64-elf", "x86_64-unknown-alix", "x86_64-alix"):
            raise RuntimeError(f"refusing host compiler target {target}: use an Alix cross compiler")
        for name, program in PROBES.items():
            # The cross compiler's own include paths are intentional; the host
            # macOS/Linux SDK must not conceal holes in the Alix sysroot.
            result = subprocess.run(
                [compiler, "-x", "c++", "-std=c++17", "-ffreestanding", "-fno-builtin",
                 "-fsyntax-only", "-I" + str(ROOT / "include"),
                 "-I" + str(ROOT / "user/lib"), "-"], input=program,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                env={key: value for key, value in os.environ.items()
                     if key not in ("CPATH", "CPLUS_INCLUDE_PATH", "C_INCLUDE_PATH", "SDKROOT")})
            (output / (name + ".log")).write_text(result.stdout)
            print(f"{'DECLARED' if result.returncode == 0 else 'MISSING'}: {name} (compile only)")
    else:
        print(f"MISSING: Alix C++ cross compiler {compiler}")
    print(f"Compiler diagnostics: {output}")
    print("Unimplemented: Mozilla/Rust Alix target, NSPR, Gecko widget/compositor backend,")
    print("process IPC, shared memory, and the remaining libc/VM/threading contracts.")
    print("Header compilation is not a link test or proof of working runtime semantics.")
    print("See docs/zen_port.md for ordered implementation and acceptance gates.")
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("fetch", "fetch-engine", "preflight"))
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--engine-dir", type=Path)
    parser.add_argument("--engine-archive", type=Path)
    args = parser.parse_args()
    manifest = load_manifest()
    source = args.source_dir.absolute()
    if args.action == "fetch-engine":
        parent = Path(__file__).parent / "upstream"
        name = "firefox-" + manifest["firefox_version"]
        engine = args.engine_dir or parent / name
        archive = args.engine_archive or parent / (name + ".source.tar.xz")
        fetch_engine(engine.absolute(), archive.absolute(), manifest)
        return 0
    if args.action == "fetch":
        fetch_source(source, manifest)
        return 0
    return preflight(source, manifest)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError, tarfile.TarError) as error:
        print(f"Zen source preparation failed: {error}", file=sys.stderr)
        sys.exit(1)
