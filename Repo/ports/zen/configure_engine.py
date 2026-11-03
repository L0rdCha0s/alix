#!/usr/bin/env python3
"""Configure/build upstream SpiderMonkey or Gecko with Alix's native runtime."""
import argparse
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

from patch_engine import apply_patches
from configure_cache import refresh_compiler_cache, rust_port_revision
from toolchain.target_driver import native_bindgen_flags

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine-dir", type=Path, default=ROOT / "ports/zen/upstream/firefox-159.0")
    parser.add_argument("--project", choices=("js", "browser"), default="js")
    parser.add_argument("--build", action="store_true", help="run the actual upstream build after configuration")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--keep-going", action="store_true",
                        help="use upstream mach's supported mode to collect independent build failures")
    args = parser.parse_args()
    label = "SpiderMonkey" if args.project == "js" else "Gecko"
    log_prefix = "spidermonkey" if args.project == "js" else "gecko"
    engine = args.engine_dir.resolve()
    object_dir = engine.parent / ("obj-js-alix" if args.project == "js" else "obj-gecko-alix")
    zen = None
    if args.project == "browser" and (engine / ".alix-zen-overlay.json").exists():
        from import_zen import verify_active_overlay
        zen = verify_active_overlay(engine)
        label = "Zen"
    apply_patches(engine)
    objects = shlex.split(os.environ.get("ALIX_RUNTIME_OBJECTS", ""))
    if not objects:
        raise RuntimeError("use make zen-js-configure or zen-gecko-configure to supply Alix runtime objects")
    state = ROOT / "ports/zen/upstream/alix-toolchain"
    state.mkdir(parents=True, exist_ok=True)
    pkgconfig = state / "pkgconfig-alix"
    pkgconfig.mkdir(exist_ok=True)
    manifest = state / "runtime-objects.json"
    temporary_manifest = manifest.with_name(f".{manifest.name}.{os.getpid()}.tmp")
    temporary_manifest.write_text(json.dumps([str((ROOT / obj).resolve()) for obj in objects], indent=2) + "\n")
    temporary_manifest.replace(manifest)
    config = state / ("mozconfig-js-alix" if args.project == "js" else "mozconfig-gecko-alix")
    config.write_text("\n".join([
        "# Native Alix target; no host-browser or Linux ABI fallback.",
        "mk_add_options MOZ_OBJDIR=" + shlex.quote(str(object_dir)),
        "ac_add_options --target=x86_64-unknown-alix",
        "ac_add_options --enable-project=" + args.project,
        *(["ac_add_options --enable-default-toolkit=cairo-alix"] if args.project == "browser" else []),
        "ac_add_options --disable-bootstrap",
        *(["ac_add_options --disable-shared-js"] if args.project == "js" else []),
        "ac_add_options --disable-tests",
        "ac_add_options --disable-debug",
        "ac_add_options --enable-optimize",
        "ac_add_options --without-system-zlib",
        *([
            "ac_add_options --with-app-name=zen",
            "ac_add_options --with-app-basename=Zen",
            "ac_add_options --with-branding=browser/branding/release",
            "ac_add_options --with-distribution-id=app.zen-browser",
            "ac_add_options --with-l10n-base=" + shlex.quote(str(engine / "browser/locales")),
            "ac_add_options --enable-update-channel=release",
            "export MOZ_APP_BASENAME=Zen",
            "export MOZ_BRANDING_DIRECTORY=browser/branding/release",
            "export MOZ_OFFICIAL_BRANDING_DIRECTORY=browser/branding/release",
            "export ACCEPTED_MAR_CHANNEL_IDS=release",
            "export MAR_CHANNEL_ID=release",
            "export ZEN_FIREFOX_VERSION=" + json.loads((ROOT / "ports/zen/upstream.json").read_text())["firefox_version"],
            "export MOZ_APPUPDATE_HOST=updates.zen-browser.app",
        ] if zen else []),
        "",
    ]))
    env = os.environ.copy()
    for variable in ("CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "SDKROOT"):
        env.pop(variable, None)
    env.update({
        "MOZCONFIG": str(config), "MOZBUILD_STATE_PATH": str(ROOT / "ports/zen/upstream/mozbuild-state"),
        "MACH_NO_UV": "1", "MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE": "none",
        "PYTHONDONTWRITEBYTECODE": "1", "ALIX_RUNTIME_MANIFEST": str(manifest),
        "CC": str(ROOT / "ports/zen/toolchain/alix-clang"),
        "CXX": str(ROOT / "ports/zen/toolchain/alix-clang++"),
        "HOST_CC": shutil.which("cc") or "cc", "HOST_CXX": shutil.which("c++") or "c++",
        # Standalone SpiderMonkey otherwise defaults to the host's pkg-config
        # zlib. Only explicitly installed Alix metadata may be discovered.
        "PKG_CONFIG_LIBDIR": str(pkgconfig), "PKG_CONFIG_PATH": "", "PKG_CONFIG_SYSROOT_DIR": "",
    })
    wasi_receipt = None
    if args.project == "browser":
        # Gecko C++ uses constant FP expressions in aggregate initializers.
        # Its application code expects the default rounding environment;
        # Alix's C math runtime retains its separately compiled fenv semantics.
        env.setdefault("CXXFLAGS", "-fno-rounding-math")
        # Codec/library sandboxes use real wasm32-wasip1 code. The native Alix
        # driver has x86/TLS/ABI flags and is not a WASI compiler substitute.
        from wasi_sdk import selected_sdk, verify
        specification, selected, wasi = selected_sdk()
        if not wasi.is_dir():
            raise RuntimeError("run make zen-wasi-sdk to install the pinned sandbox compiler/sysroot")
        verify(wasi, specification, selected)
        env.setdefault("WASM_CC", str(wasi / "bin/clang"))
        env.setdefault("WASM_CXX", str(wasi / "bin/clang++"))
        env.setdefault("WASI_SYSROOT", str(wasi / "share/wasi-sysroot"))
        wasi_receipt = wasi / "alix-sdk-receipt.json"
    rust_wrapper = ROOT / "ports/zen/rust/rustc.py"
    rust_profile = "rust-alix-pic" if args.project == "browser" else "rust-alix"
    rust_sysroot = ROOT / ("ports/zen/upstream/" + rust_profile + "-sysroot")
    rust_specification = ROOT / "ports/zen/rust" / (
        "pic/x86_64-unknown-alix.json" if args.project == "browser" else "x86_64-unknown-alix.json")
    if rust_wrapper.is_file() and rust_specification.is_file():
        env.setdefault("RUSTC", str(rust_wrapper))
        env.setdefault("RUST_TARGET_SPEC", str(rust_specification))
        env.setdefault("ALIX_RUST_SYSROOT", str(rust_sysroot))
        selected_specification = Path(env["RUST_TARGET_SPEC"]).expanduser().resolve()
        env["RUST_TARGET_SPEC"] = str(selected_specification)
        env["RUST_TARGET_PATH"] = str(selected_specification.parent)
        env.setdefault("RUSTC_BOOTSTRAP", "1")
        # Cargo assumes the compiler sysroot is immutable. The Alix runtime
        # publishes immutable snapshots, so include their content identifier in
        # target-crate fingerprints when the selected snapshot changes. This
        # cfg is deliberately unused by source and changes no engine feature.
        native_std = (Path(env["ALIX_RUST_SYSROOT"]) / "lib/rustlib/x86_64-unknown-alix/lib").resolve(strict=True)
        snapshot = re.fullmatch(r"rust-alix-stdlib-([0-9a-f]{16})", native_std.name)
        if not snapshot:
            raise RuntimeError("native Rust sysroot must select a managed immutable std snapshot")
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") +
                            " --cfg=alix_std_snapshot_" + snapshot.group(1) +
                            " --cfg=alix_rust_port_" + rust_port_revision(
                                ROOT / "ports/zen/patches/series.json")).strip()
        # bindgen invokes libclang directly and never enters alix-clang++.
        # Use its target-specific environment override so host build tools keep
        # their own ABI/includes even when Mozilla supplies global arguments.
        variable = "BINDGEN_EXTRA_CLANG_ARGS_x86_64_unknown_alix"
        env[variable] = shlex.join(native_bindgen_flags() + shlex.split(env.get(variable, "")))
    tools = json.loads((ROOT / "ports/zen/host-tools.json").read_text())
    cbindgen = ROOT / "ports/zen/upstream/tools" / ("cbindgen-" + tools["cbindgen"]["version"]) / "bin/cbindgen"
    if cbindgen.is_file():
        env.setdefault("CBINDGEN", str(cbindgen))
    llvm = Path(env.get("ALIX_LLVM_PREFIX", "/opt/homebrew/opt/llvm"))
    for variable, executable in {
        "AR": llvm / "bin/llvm-ar", "RANLIB": llvm / "bin/llvm-ranlib",
        "LLVM_PROFDATA": llvm / "bin/llvm-profdata", "LLVM_OBJDUMP": llvm / "bin/llvm-objdump",
        "READELF": Path(shutil.which("x86_64-elf-readelf") or ""),
        "NM": Path(shutil.which("x86_64-elf-nm") or ""),
        "OBJCOPY": Path(shutil.which("x86_64-elf-objcopy") or ""),
        "STRIP": Path(shutil.which("x86_64-elf-strip") or ""),
    }.items():
        if not executable.is_file():
            raise RuntimeError(f"required native tool is missing: {variable}={executable}")
        env[variable] = str(executable)
    output = ROOT / "build/ports/zen"
    output.mkdir(parents=True, exist_ok=True)
    log = output / (log_prefix + "-configure.log")
    python = os.environ.get("MOZ_PYTHON", shutil.which("python3.13") or sys.executable)
    runtime = ROOT / "ports/zen/upstream/libcxx-alix-build"
    compiler_resource = Path(subprocess.check_output(
        [str(llvm / "bin/clang"), "--no-default-config", "-print-resource-dir"], text=True).strip())
    compiler_inputs = [ROOT / obj for obj in objects]
    for directory in (ROOT / "include", runtime / "include/c++/v1", compiler_resource / "include"):
        compiler_inputs.extend(path for path in directory.rglob("*") if path.is_file())
    compiler_inputs.extend((ROOT / "user/lib").rglob("*.h"))
    compiler_inputs.extend((ROOT / "ports/zen/toolchain").glob("*.py"))
    compiler_inputs.extend([
        ROOT / "user/lib/link.ld", ROOT / "ports/zen/toolchain/alix-clang",
        ROOT / "ports/zen/toolchain/alix-clang++", ROOT / "ports/zen/libcxx/__external_threading",
        ROOT / "ports/zen/libcxx/__alix_locale",
        runtime / "lib/libc++.a", runtime / "lib/libc++abi.a", runtime / "lib/libalix-cxx-support.a",
        ROOT / "ports/zen/upstream/libm-alix-build/lib/libalix-math.a",
        ROOT / "build/user/lib/libalix-ssp.a", Path(__file__), Path(__file__).with_name("configure_cache.py"),
    ])
    if wasi_receipt is not None:
        compiler_inputs.extend([wasi_receipt, ROOT / "ports/zen/host-tools.json", Path(__file__).with_name("wasi_sdk.py")])
    refresh_compiler_cache(object_dir, state / ("configure-cache-" + args.project), compiler_inputs)
    print(f"Configuring upstream {label} for native Alix; diagnostics: {log}", flush=True)
    with log.open("w") as stream:
        result = subprocess.run([python, str(engine / "mach"), "configure"], cwd=engine,
                                env=env, stdout=stream, stderr=subprocess.STDOUT)
    print("\n".join(line[:1000] for line in log.read_text(errors="replace").splitlines()[-35:]))
    print(f"Upstream configure exit status: {result.returncode}")
    if result.returncode == 0 and args.build:
        if args.jobs < 1:
            raise RuntimeError("--jobs must be positive")
        log = output / (log_prefix + "-build.log")
        print(f"Building real upstream {label}; diagnostics: {log}", flush=True)
        with log.open("w") as stream:
            result = subprocess.run([python, str(engine / "mach"), "build", "--priority", "normal",
                                     "-j", str(args.jobs)] + (["--keep-going"] if args.keep_going else []),
                                    cwd=engine, env=env, stdout=stream, stderr=subprocess.STDOUT)
        print("\n".join(line[:1000] for line in log.read_text(errors="replace").splitlines()[-50:]))
        print(f"Upstream build exit status: {result.returncode}")
    (output / (log_prefix + "-command-status.txt")).write_text(str(result.returncode) + "\n")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
