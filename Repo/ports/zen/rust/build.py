#!/usr/bin/env python3
"""Build upstream Rust std for the explicit native Alix target and smoke ELF."""
import os
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import shlex
import subprocess
import sys

from prepare import HERE, ROOT, SOURCE, SYSROOT, prepare

def install_std(libraries, sysroot=SYSROOT):
    """Publish one immutable native std set, preserving older build snapshots."""
    libraries = sorted(set(map(Path, libraries)))
    if not any(path.name.startswith("libstd-") and path.suffix == ".rlib" for path in libraries):
        raise RuntimeError("no compiled native std library to install")
    digest = hashlib.sha256()
    for path in libraries:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    snapshot = HERE.parent / ("upstream/rust-alix-stdlib-" + digest.hexdigest()[:16])
    if not snapshot.exists():
        snapshot.mkdir()
        for path in libraries: shutil.copyfile(path, snapshot / path.name)
    target = sysroot / "lib/rustlib/x86_64-unknown-alix"
    target.mkdir(parents=True, exist_ok=True)
    destination = target / "lib"
    if destination.exists() and not destination.is_symlink():
        raise RuntimeError("native sysroot lib directory is not a managed symlink; left untouched")
    temporary = target / "lib.new"
    if temporary.exists() or temporary.is_symlink():
        raise RuntimeError("native sysroot publication already pending; left untouched")
    temporary.symlink_to(snapshot, target_is_directory=True)
    os.replace(temporary, destination)
    print(f"Native std snapshot installed: {snapshot}")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-publish-smoke", action="store_true",
                        help="build/link the smoke ELF in the cache without replacing the guest fixture")
    parser.add_argument("--pic", action="store_true",
                        help="build the PIC/dynamic-TLS std used by Gecko shared libraries")
    args = parser.parse_args()
    profile = "rust-alix-pic" if args.pic else "rust-alix"
    sysroot = HERE.parent / ("upstream/" + profile + "-sysroot")
    specification = HERE / ("pic/x86_64-unknown-alix.json" if args.pic else "x86_64-unknown-alix.json")
    prepare(sysroot)
    for wrapper in (HERE / "rustc.py", HERE / "linker.py"):
        wrapper.chmod(wrapper.stat().st_mode | 0o111)
    cargo_home = HERE.parent / "upstream/rust-alix-cargo"
    cargo_home.mkdir(exist_ok=True)
    (cargo_home / "config.toml").write_text(
        '[source.crates-io]\nreplace-with = "alix-vendor"\n\n[source.alix-vendor]\n'
        f'directory = "{SOURCE / "library/vendor"}"\n')
    target_dir = HERE.parent / ("upstream/" + profile + "-target")
    # Cargo treats rust-src sysroot packages as immutable and can otherwise
    # reuse std after a PAL edit. A source-derived cfg changes its fingerprint.
    source_hash = hashlib.sha256()
    for path in sorted(list((HERE / "overlay").rglob("*.rs")) +
                       [HERE / "prepare.py", HERE / "upstream.json", specification]):
        source_hash.update(str(path.relative_to(HERE)).encode())
        source_hash.update(path.read_bytes())
    revision = source_hash.hexdigest()
    env = os.environ.copy()
    native_objects = [ROOT / item for item in shlex.split(env.get("ALIX_RUNTIME_OBJECTS", ""))]
    if not native_objects:
        raise RuntimeError("ALIX_RUNTIME_OBJECTS must name the native Alix runtime objects")
    libgcc = Path(subprocess.check_output(["x86_64-elf-gcc", "-print-libgcc-file-name"], text=True).strip())
    native_link_inputs = native_objects + [ROOT / "user/lib/link.ld", HERE / "linker.py", libgcc,
        HERE.parent / "upstream/libcxx-alix-build/lib/libc++.a",
        HERE.parent / "upstream/libcxx-alix-build/lib/libc++abi.a",
        HERE.parent / "upstream/libcxx-alix-build/lib/libalix-cxx-support.a",
        HERE.parent / "upstream/libm-alix-build/lib/libalix-math.a",
        ROOT / "build/user/lib/libalix-ssp.a"]
    env.update({"RUSTC_BOOTSTRAP": "1", "RUSTC": str(HERE / "rustc.py"),
                "ALIX_REAL_RUSTC": shutil.which("rustc"), "CARGO_HOME": str(cargo_home),
                "ALIX_RUST_SYSROOT": str(sysroot), "RUST_TARGET_SPEC": str(specification),
                "CARGO_TARGET_DIR": str(target_dir),
                "ALIX_RUNTIME_LINK_INPUTS": "\n".join(str(path.resolve()) for path in native_link_inputs),
                "CARGO_ENCODED_RUSTFLAGS": "\x1f".join([
                    "-Zunstable-options", "-Cpanic=abort", "-Clink-dead-code=no", "-Cembed-bitcode=yes",
                    "--cfg", 'alix_std_revision="' + revision + '"',
                    "-Clinker=" + str(HERE / "linker.py")])})
    command = ["cargo", "build", "--offline", "--release", "-j", "4", "--message-format=json-render-diagnostics",
                    "-Zjson-target-spec", "-Zbuild-std=std,panic_abort", "-Zbuild-std-features=optimize_for_size",
                    "--target", str(specification),
                    "--manifest-path", str(HERE / "smoke/Cargo.toml")]
    process = subprocess.Popen(command, cwd=HERE / "smoke", env=env, stdout=subprocess.PIPE, text=True)
    libraries = []
    for line in process.stdout:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            print(line, end="", flush=True)
            continue
        if message.get("reason") == "compiler-artifact":
            for filename in message.get("filenames", []):
                path = Path(filename)
                if path.is_relative_to(target_dir / "x86_64-unknown-alix") and path.suffix in (".rlib", ".rmeta"):
                    libraries.append(path)
        elif message.get("reason") == "compiler-message":
            print(message["message"].get("rendered", message["message"]["message"]), flush=True)
    if process.wait() != 0:
        raise subprocess.CalledProcessError(process.returncode, command)
    (target_dir / "alix-artifacts.json").write_text(json.dumps({
        "overlay_revision": revision, "libraries": list(map(str, sorted(set(libraries))))
    }, indent=2) + "\n")
    install_std(libraries, sysroot)
    binary = target_dir / "x86_64-unknown-alix/release/alix-rust-std-test"
    output = ROOT / "build/user/rust_std_test.elf"
    undefined = subprocess.check_output(["x86_64-elf-nm", "--undefined-only", str(binary)], text=True)
    if undefined.strip(): raise RuntimeError("Rust native ELF has unresolved symbols: " + undefined)
    if not args.no_publish_smoke and not args.pic:
        temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
        shutil.copyfile(binary, temporary)
        temporary.replace(output)
        print(f"Real Rust std native acceptance ELF: {output}")
    else:
        print(f"Real Rust std native acceptance ELF retained in cache: {binary}")

if __name__ == "__main__":
    main()
