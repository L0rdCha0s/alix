"""Refresh compiler probes when the native Alix SDK changes at fixed paths."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile


def rust_port_revision(series_path):
    """Invalidate Cargo's immutable vendor cache when native bindings change.

    apply_patches verifies these digests against actual files before this is
    used. Non-Rust changes do not discard otherwise reusable Rust compilation.
    Ordinary in-tree path crates can opt out: Cargo already tracks their source
    files. Registry/vendor inputs always invalidate the global token.
    """
    series = json.loads(Path(series_path).read_text())
    inputs = {}
    for entry in series["patches"]:
        invalidate = entry.get("rust_vendor_cache", True)
        if not isinstance(invalidate, bool):
            raise RuntimeError("rust_vendor_cache must be a boolean")
        for item in entry["files"]:
            if (item["path"].startswith("third_party/rust/") or
                    (invalidate and item["path"].endswith(".rs"))):
                inputs[item["path"]] = item["after"]
    fingerprint = hashlib.sha256()
    for name, digest in sorted(inputs.items()):
        fingerprint.update(name.encode() + b"\0" + digest.encode() + b"\0")
    return fingerprint.hexdigest()[:16]


def refresh_compiler_cache(object_dir, state_dir, inputs):
    fingerprint = hashlib.sha256()
    # Resolve installed header/library symlinks, then hash actual content. A
    # missing input must fail before touching any existing compiler results.
    paths = sorted({Path(path).resolve(strict=True) for path in inputs})
    for path in paths:
        if not path.is_file():
            raise RuntimeError(f"native configure input is not a regular file: {path}")
        fingerprint.update(str(path).encode() + b"\0")
        with path.open("rb") as source:
            before = os.fstat(source.fileno())
            fingerprint.update(before.st_size.to_bytes(8, "big"))
            while chunk := source.read(1024 * 1024):
                fingerprint.update(chunk)
            after = os.fstat(source.fileno())
        current = path.stat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise RuntimeError(f"native configure input changed during hashing: {path}")
        fingerprint.update(b"\0")
    revision = fingerprint.hexdigest()
    state_dir = Path(state_dir)
    stamp = state_dir / "configure-input.sha256"
    if stamp.is_file() and stamp.read_text().strip() == revision:
        return revision

    cache = Path(object_dir) / "configure.cache"
    try:
        cache_mode = cache.lstat().st_mode
    except FileNotFoundError:
        cache_mode = None
    if cache_mode is not None and not stat.S_ISREG(cache_mode):
        raise RuntimeError(f"compiler cache is not a regular file: {cache}")
    state_dir.mkdir(parents=True, exist_ok=True)
    if cache_mode is not None:
        history = state_dir / "configure-cache-history"
        history.mkdir(exist_ok=True)
        cache_digest = hashlib.sha256(cache.read_bytes()).hexdigest()[:16]
        descriptor, name = tempfile.mkstemp(prefix=cache_digest + "-", suffix=".cache", dir=history)
        os.close(descriptor)
        backup = Path(name)
        try:
            cache.replace(backup)
        except BaseException:
            backup.unlink()
            raise
        print(f"Archived stale compiler-probe cache: {backup}", flush=True)
    descriptor, name = tempfile.mkstemp(prefix=".configure-input-", dir=state_dir)
    with os.fdopen(descriptor, "w") as output:
        output.write(revision + "\n")
    Path(name).replace(stamp)
    return revision
