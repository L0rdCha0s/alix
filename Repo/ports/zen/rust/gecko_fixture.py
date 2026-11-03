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
import tomllib

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SPEC = HERE.parent / "upstream/obj-gecko-alix/toolkit/library/rust/.cargo-library-spec.json"

FIXTURES = {
    "neqo-udp": {
        "packages": ("neqo-udp",), "externs": ("neqo_udp", "neqo_common"), "harness": True,
        "dependencies": {"neqo-udp": {"version": "=0.32.0"}, "neqo-common": {"version": "=0.32.0"}},
        "source": "tests/rust_neqo_udp.rs", "elf": "rust_neqo_udp_test.elf",
    },
    "quinn-udp": {
        "packages": ("quinn-udp",), "externs": ("quinn_udp",), "harness": True,
        "no_default_features": True,
        "dependencies": {"quinn-udp": {"version": "=0.6.2"}},
        "source": "tests/rust_quinn_udp.rs", "abi": "tests/udp_socket_api_test.c",
        "elf": "rust_quinn_udp_test.elf",
    },
    "socket2": {
        "packages": ("socket2",), "externs": ("socket2", "libc"), "harness": True,
        "no_default_features": True,
        "dependencies": {"socket2": {"version": "=0.6.3", "features": ["all"]}},
        "source": "tests/rust_socket2.rs", "abi": "tests/rust_socket2_abi.c",
        "elf": "rust_socket2_test.elf",
    },
    "socket2-check": {
        "packages": ("socket2",), "externs": ("socket2",), "harness": True,
        "no_default_features": True, "check_only": True,
        "dependencies": {"socket2": {"version": "=0.6.3", "features": ["all"]}},
    },
    "mtu": {
        "packages": ("mtu",), "externs": ("mtu",), "harness": True,
        "no_default_features": True,
        "dependencies": {"mtu": {"version": "=0.4.1"}},
        "source": "tests/rust_mtu.rs", "abi": "tests/network_route_test.c",
        "elf": "rust_mtu_test.elf",
    },
    "glyphs-gecko-check": {
        "packages": ("wr_glyph_rasterizer",), "externs": ("wr_glyph_rasterizer",),
        "no_default_features": True, "check_only": True, "harness": True,
        "dependencies": {
            "wr_glyph_rasterizer": {"path": "gfx/wr/wr_glyph_rasterizer",
                                    "features": ["gecko", "capture"]},
        },
    },
    "glyphs": {
        "packages": ("wr_glyph_rasterizer",),
        "externs": ("wr_glyph_rasterizer", "webrender_api", "libz_rs_sys"),
        "no_default_features": True, "harness": True,
        "source": "tests/rust_glyph_rasterizer.rs", "elf": "rust_glyph_rasterizer_test.elf",
        "link_args": ("build/ports/zen/libalix-gecko-fonts.a",),
        "dependencies": {
            "wr_glyph_rasterizer": {"path": "gfx/wr/wr_glyph_rasterizer"},
            "webrender_api": {"path": "gfx/wr/webrender_api"},
            "libz-rs-sys": {"version": "=0.6.3", "features": ["std", "rust-allocator", "custom-prefix"]},
        },
    },
    "network-check": {
        "packages": ("rustix@1.1.4",), "externs": ("rustix",),
        "features": ("fs", "net"), "no_default_features": True,
        "check_only": True, "harness": True,
    },
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
    if fixture.get("check_only") or fixture.get("harness"):
        # Vendor packages are immutable to Cargo. Targeted checks must also
        # invalidate when a managed Rust patch changes between configure runs.
        from configure_cache import rust_port_revision
        env["RUSTFLAGS"] += " --cfg alix_component_port_" + rust_port_revision(HERE.parent / "patches/series.json")
    argv = compose_cargo_build_edge_argv(command, config, invocation)
    argv[2:2] = ["-j4", "--keep-going"]
    if not fixture.get("root_graph"):
        argv = argv[:argv.index("--")]
        argv[1] = "build"
        if not fixture.get("harness"):
            for package in fixture["packages"]:
                argv.extend(["--package", package])
        # URL is selected from Gecko's dependency set with package defaults.
        # The OS consumers instead require the complete configured root graph:
        # several are reachable only through gkrust's explicit feature set.
        index = argv.index("--features")
        del argv[index:index + 2]
        if fixture.get("no_default_features"):
            argv.append("--no-default-features")
        if fixture.get("features"):
            argv.extend(["--features", ",".join(fixture["features"])])
    if fixture.get("harness"):
        # Cargo disallows selecting registry-package features with -p. A small
        # consumer selects the same locked vendor package and required features
        # while retaining Gecko's configured compiler/environment and source map.
        harness = ROOT / "build/ports/zen" / ("rust-" + name + "-consumer")
        harness.mkdir(parents=True, exist_ok=True)
        dependencies = fixture.get("dependencies", {"rustix": {"version": "=1.1.4"}})
        manifest_lines = ["[package]", "name = " + json.dumps("alix-gecko-" + name),
                          'version = "0.1.0"', 'edition = "2021"', "[workspace]",
                          "[lib]", 'path = "lib.rs"', "[features]", "default = []"]
        for feature in fixture.get("features", ()):
            manifest_lines.append(feature + " = " + json.dumps(
                [dependency + "/" + feature for dependency in dependencies]))
        for dependency, options in dependencies.items():
            manifest_lines.extend(["[dependencies." + dependency + "]", "default-features = false"])
            for key, value in options.items():
                if key == "path":
                    value = str(Path(source) / value)
                manifest_lines.append(key + " = " + json.dumps(value))
        # Path dependencies do not inherit their parent workspace's patch
        # table. Keep Gecko's local adapters and pinned Git replacements.
        workspace = tomllib.loads((Path(source) / "Cargo.toml").read_text())
        for registry, patches in workspace.get("patch", {}).items():
            for package, options in patches.items():
                manifest_lines.append("[patch." + json.dumps(registry) + "." + json.dumps(package) + "]")
                for key, value in options.items():
                    if key == "path":
                        value = str(Path(source) / value)
                    manifest_lines.append(json.dumps(key) + " = " + json.dumps(value))
        manifest_text = "\n".join(manifest_lines) + "\n"
        (harness / "Cargo.toml").write_text(manifest_text)
        (harness / "lib.rs").write_text("".join("pub use " + dependency.replace("-", "_") + ";\n"
                                                 for dependency in dependencies))
        manifest = str(harness / "Cargo.toml")
        argv[argv.index("--manifest-path") + 1] = manifest
        source_lock = (Path(source) / "Cargo.lock").read_bytes()
        lock_inputs = hashlib.sha256(manifest_text.encode() + b"\0" + source_lock).hexdigest()
        lock_stamp = harness / "lock-inputs.sha256"
        if (not (harness / "Cargo.lock").exists() or not lock_stamp.exists() or
                lock_stamp.read_text().strip() != lock_inputs):
            # Cargo's vendored Git replacements require the original pinned
            # source identities from Gecko's lock before resolving the consumer.
            (harness / "Cargo.lock").write_bytes(source_lock)
        # Unlike generate-lockfile, metadata preserves the pinned Git revisions
        # while pruning the copied workspace lock to this consumer's graph.
        subprocess.run([argv[0], "metadata", "--offline", "--format-version=1",
                        "--manifest-path", manifest], cwd=command.working_directory,
                       env=env, stdout=subprocess.DEVNULL, check=True)
        lock_stamp.write_text(lock_inputs + "\n")
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
    if fixture.get("check_only"):
        for artifact in artifacts.values():
            artifact["sha256"] = hashlib.sha256(Path(artifact["path"]).read_bytes()).hexdigest()
        (output_dir / f"rust-{name}-native-compile.json").write_text(json.dumps({
            "scope": "Configured Gecko package compilation; runtime is a separate gate",
            "std_snapshot": snapshot.name, "cargo_command": argv, "cargo_exit": cargo_exit,
            "rustflags": env["RUSTFLAGS"],
            "spec_sha256": hashlib.sha256(spec_bytes).hexdigest(), "libraries": artifacts,
        }, indent=2) + "\n")
        print("Configured native package compilation: PASS", name)
        return
    extra_args = []
    for argument in fixture.get("link_args", ()):
        extra_args.append("-Clink-arg=" + str(ROOT / argument))
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
