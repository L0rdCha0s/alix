#!/usr/bin/env python3
"""Build pinned Mozilla host tools in the port's own cache, never globally."""
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    manifest = json.loads(Path(__file__).with_name("host-tools.json").read_text())
    version = manifest["cbindgen"]["version"]
    prefix = ROOT / "ports/zen/upstream/tools" / ("cbindgen-" + version)
    executable = prefix / "bin/cbindgen"
    if not executable.exists():
        env = os.environ.copy()
        for key in ("RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS",
                    "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "RUST_TARGET_PATH",
                    "RUSTC_BOOTSTRAP", "CARGO_TARGET_X86_64_UNKNOWN_ALIX_LINKER"):
            env.pop(key, None)
        env["CARGO_HOME"] = str(ROOT / "ports/zen/upstream/host-cargo")
        env["CARGO_TARGET_DIR"] = str(ROOT / "ports/zen/upstream/host-cargo-target")
        subprocess.run([shutil.which("cargo") or "cargo", "install", "cbindgen",
                        "--version", "=" + version, "--locked", "--root", str(prefix), "-j", "2"],
                       env=env, check=True)
    actual = subprocess.check_output([str(executable), "--version"], text=True).strip()
    if actual != "cbindgen " + version:
        raise RuntimeError(f"existing workspace cbindgen does not match pin: {actual}")
    print(f"Verified host tool {actual}: {executable}")


if __name__ == "__main__":
    main()
