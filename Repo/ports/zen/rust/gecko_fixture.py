#!/usr/bin/env python3
"""Build real Gecko Rust packages and link native Alix acceptance programs."""
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = HERE.parent / "upstream/obj-gecko-alix/toolkit/library/rust/.cargo-library-spec.json"

FIXTURES = {
    "file-urls": {
        "packages": ("url",), "externs": ("url",),
        "source": "tests/rust_file_urls.rs", "elf": "rust_file_urls_test.elf",
    },
    "os-consumers": {
        "packages": ("glean-core", "kvstore", "errno", "processtools"),
        "root_graph": True,
        "required": ("glean_core", "kvstore", "errno", "processtools"),
        "externs": ("glean_core", "errno", "libc", "log", "serde_json"),
        "source": "tests/rust_os_consumers.rs", "elf": "rust_os_consumers_test.elf",
        "abi": "tests/rust_os_consumers_abi.c",
    },
    "directories": {
        "packages": ("dirs", "dirs-sys"), "root_graph": True,
        "required": ("dirs", "dirs_sys", "glean_core", "kvstore", "errno", "processtools"),
        "externs": ("dirs", "dirs_sys", "libc"),
        "source": "tests/rust_directories.rs", "elf": "rust_directories_test.elf",
        "abi": "tests/rust_directories_abi.c",
    },
}


def run(name):
    fixture = FIXTURES[name]
    spec_bytes = SPEC.read_bytes()
    spec = json.loads(spec_bytes)
    # Use Gecko's configured virtualenv for its real Cargo command composer.
    if sys.argv[1:] != ["--configured"]:
        subprocess.run([spec["config"]["PYTHON3"], str(Path(sys.argv[0]).resolve()), "--configured"],
                       cwd=ROOT, check=True)
        return
    from mozbuild.rust_commands import (CargoInvocation, compose_cargo_build_edge_argv,
                                       compose_env, load_cargo_spec)
    sys.path.insert(0, str(HERE.parent))
    from toolchain.target_driver import native_bindgen_flags

    command, config, source, obj = load_cargo_spec(spec)
    base = dict(os.environ)
    for key in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "SDKROOT"):
        base.pop(key, None)
    base.update({
        "RUST_TARGET_SPEC": str(HERE / "x86_64-unknown-alix.json"),
        "RUST_TARGET_PATH": str(HERE),
        "MOZCONFIG": str(HERE.parent / "upstream/alix-toolchain/mozconfig-gecko-alix"),
        "MOZBUILD_STATE_PATH": str(HERE.parent / "upstream/mozbuild-state"),
        "ALIX_RUNTIME_MANIFEST": str(HERE.parent / "upstream/alix-toolchain/runtime-objects.json"),
        "BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_alix": shlex.join(native_bindgen_flags()),
        "CARGO_NET_OFFLINE": "true", "RUSTC_BOOTSTRAP": "1",
    })
    invocation = dataclasses.replace(CargoInvocation.from_environ(base), json_output=True)
    env = compose_env(command, config, base, invocation, source, obj)
    snapshot = (HERE.parent / "upstream/rust-alix-sysroot/lib/rustlib/x86_64-unknown-alix/lib").resolve()
    fingerprint = "alix_std_snapshot_" + snapshot.name.removeprefix("rust-alix-stdlib-")
    if fingerprint not in env["RUSTFLAGS"]:
        raise RuntimeError("Gecko configure does not match the selected native std snapshot")
    argv = compose_cargo_build_edge_argv(command, config, invocation)
    argv[2:2] = ["-j4", "--keep-going"]
    if not fixture.get("root_graph"):
        argv = argv[:argv.index("--")]
        argv[1] = "build"
        for package in fixture["packages"]:
            argv.extend(["--package", package])
        # URL is selected from Gecko's dependency set with package defaults.
        # The OS consumers instead require the complete configured root graph:
        # several are reachable only through gkrust's explicit feature set.
        index = argv.index("--features")
        del argv[index:index + 2]
    native_dir = Path(obj) / "x86_64-unknown-alix"
    artifacts = {}
    artifact_issues = []
    wanted = set(fixture["externs"]) | set(fixture.get("required", ()))
    failed_packages = set()
    process = subprocess.Popen(argv, cwd=command.working_directory, env=env,
                               stdout=subprocess.PIPE, text=True)
    for line in process.stdout:
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            print(line, end="", flush=True)
            continue
        if message.get("reason") == "compiler-message":
            print(message["message"].get("rendered", message["message"]["message"]), flush=True)
            if message["message"].get("level") == "error":
                failed_packages.add(message["package_id"])
        elif message.get("reason") == "compiler-artifact":
            if message.get("target", {}).get("name") not in wanted:
                continue
            libraries = [Path(p) for p in message["filenames"]
                         if p.endswith(".rlib") and Path(p).is_relative_to(native_dir)]
            if not libraries:
                continue
            if len(libraries) != 1:
                artifact_issues.append(f"ambiguous native library artifacts: {libraries}")
                continue
            library = libraries[0]
            metadata = [Path(p) for p in message["filenames"] if p.endswith(".rmeta")]
            # Cargo may emit link-only rlibs with embedded metadata and no
            # separate rmeta. A hashed deps path already identifies that build.
            if len(metadata) == 1:
                hashed = metadata[0].with_suffix(".rlib")
            elif not metadata and library.parent.name == "deps":
                hashed = library
            else:
                artifact_issues.append(f"cannot identify hashed native artifact: {library}")
                continue
            if hashed.read_bytes() != library.read_bytes():
                artifact_issues.append(f"Cargo alias and hashed artifact differ: {library}")
                continue
            artifacts[message["target"]["name"]] = {
                "path": str(hashed), "fresh": message.get("fresh"), "package_id": message["package_id"]}
    cargo_exit = process.wait()
    # Drain and reap Cargo before reporting collection errors; do not leave
    # child compiler processes running after a malformed artifact message.
    if artifact_issues:
        raise RuntimeError("; ".join(artifact_issues))
    if cargo_exit and not fixture.get("root_graph"):
        raise subprocess.CalledProcessError(cargo_exit, argv)
    missing = (set(fixture["externs"]) | set(fixture.get("required", ()))) - artifacts.keys()
    if missing:
        raise RuntimeError(f"required native crates were not emitted by Cargo (exit {cargo_exit}): {missing}")
    if cargo_exit:
        print(f"Gecko root remains incomplete (Cargo exit {cargo_exit}); all required native component crates emitted.", flush=True)
    output_dir = ROOT / "build/ports/zen"
    output_dir.mkdir(parents=True, exist_ok=True)
    extra_args = []
    if "abi" in fixture:
        abi = output_dir / f"rust-{name}-abi.o"
        subprocess.run([str(HERE.parent / "toolchain/alix-clang"), "-std=c11", "-c",
                        str(ROOT / fixture["abi"]), "-o", str(abi)], cwd=ROOT, env=env, check=True)
        extra_args.append("-Clink-arg=" + str(abi))
    output = ROOT / "build/user" / fixture["elf"]
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    compiler = [sys.executable, str(HERE / "rustc.py"), "--crate-name", "alix_rust_" + name.replace("-", "_"),
                "--edition=2021", "--target=x86_64-unknown-alix", "-Cpanic=abort", "-Copt-level=2",
                "-Clinker-flavor=gcc", "-Clinker=" + str(HERE.parent / "toolchain/alix-clang++"),
                "-Ldependency=" + str(native_dir / "release/deps"),
                "-Ldependency=" + str(Path(obj) / "release/deps")]
    for crate in fixture["externs"]:
        compiler.extend(["--extern", crate + "=" + artifacts[crate]["path"]])
    compiler.extend([*extra_args, str(ROOT / fixture["source"]), "-o", str(temporary)])
    try:
        subprocess.run(compiler, cwd=ROOT, env=env, check=True)
        undefined = subprocess.check_output(["x86_64-elf-nm", "--undefined-only", str(temporary)], text=True)
        if undefined.strip():
            raise RuntimeError("native fixture has unresolved symbols: " + undefined)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    sha = lambda path: hashlib.sha256(Path(path).read_bytes()).hexdigest()
    for artifact in artifacts.values():
        artifact["sha256"] = sha(artifact["path"])
    receipt = {"scope": "Actual Gecko native package compile/link; guest execution is a separate gate",
               "std_snapshot": snapshot.name, "cargo_command": argv, "cargo_exit": cargo_exit,
               "failed_packages": sorted(failed_packages), "compiler_command": compiler,
               "spec_sha256": hashlib.sha256(spec_bytes).hexdigest(), "libraries": artifacts,
               "fixture_sha256": sha(ROOT / fixture["source"]), "elf": str(output), "elf_sha256": sha(output)}
    if name == "file-urls":
        receipt.update(url_rlib=artifacts["url"]["path"], url_sha256=artifacts["url"]["sha256"])
    (output_dir / f"rust-{name}-native-link.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print("Actual Gecko native acceptance ELF:", output)
