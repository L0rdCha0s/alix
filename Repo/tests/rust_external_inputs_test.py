#!/usr/bin/env python3
"""Prove the real Cargo build script relinks on external native input changes."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="alix-rust-link-inputs-") as directory:
        project = Path(directory)
        (project / "src").mkdir()
        (project / "Cargo.toml").write_text('[package]\nname="alix-link-input-test"\nversion="0.1.0"\nedition="2024"\nbuild="build.rs"\n[workspace]\n')
        (project / "src/main.rs").write_text('fn main() { println!("host Cargo dependency test"); }\n')
        shutil.copyfile(ROOT / "ports/zen/rust/smoke/build.rs", project / "build.rs")
        native = project / "native.o"
        native.write_bytes(b"first native object")
        env = os.environ.copy()
        for variable in ("RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUST_TARGET_SPEC",
                         "RUST_TARGET_PATH", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"):
            env.pop(variable, None)
        env["ALIX_RUNTIME_LINK_INPUTS"] = str(native)
        command = ["cargo", "build", "--offline", "--manifest-path", str(project / "Cargo.toml"),
                   "--target-dir", str(project / "target")]

        def build(expect_rebuild):
            result = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
            if ("Compiling alix-link-input-test" in result.stdout) != expect_rebuild:
                raise RuntimeError("unexpected Cargo rebuild decision:\n" + result.stdout)

        build(True)
        binary = project / "target/debug/alix-link-input-test"
        original = binary.stat().st_mtime_ns
        build(False)
        native.write_bytes(b"other native object")
        build(True)
        if binary.stat().st_mtime_ns <= original:
            raise RuntimeError("Cargo did not replace the linked binary after native object change")
        extra = project / "optional-runtime.a"
        extra.write_bytes(b"archive input")
        env["ALIX_RUNTIME_LINK_INPUTS"] += "\n" + str(extra)
        build(True)
        build(False)
        env["ALIX_RUNTIME_LINK_INPUTS"] = ""
        rejected = subprocess.run(command, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if rejected.returncode == 0 or "native linker dependencies must not be empty" not in rejected.stdout:
            raise RuntimeError("missing native input tracking was silently accepted")
    print("Real Cargo external object/archive relink, unchanged-cache and missing-input contracts passed")


if __name__ == "__main__":
    main()
