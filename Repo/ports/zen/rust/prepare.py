#!/usr/bin/env python3
"""Copy matching upstream Rust library sources and apply the native Alix PAL."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = HERE.parent / "upstream/rust-1.97.1"
SYSROOT = HERE.parent / "upstream/rust-alix-sysroot"

def rust_info():
    info = subprocess.check_output(["rustc", "--version", "--verbose"], text=True)
    manifest = json.loads((HERE / "upstream.json").read_text())
    if f"commit-hash: {manifest['rust_commit']}" not in info or f"release: {manifest['rust_version']}" not in info:
        raise RuntimeError("installed rustc does not match the pinned std source/compiler revision")
    root = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
    host = next(line.split(": ", 1)[1] for line in info.splitlines() if line.startswith("host: "))
    return root, host

def prepare():
    installed, host = rust_info()
    original = installed / "lib/rustlib/src/rust/library"
    if not (original / "std/src/lib.rs").is_file():
        raise RuntimeError("matching rust-src component is required")
    if not SOURCE.exists():
        SOURCE.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".rust-source-", dir=SOURCE.parent) as temp:
            stage = Path(temp) / "rust"
            stage.mkdir()
            # Homebrew's component includes a redundant nested library tree;
            # only this workspace plus its bundled vendor directory is used.
            def ignore(directory, names):
                return {"library"} if Path(directory) == original else set()
            shutil.copytree(original, stage / "library", copy_function=shutil.copyfile, ignore=ignore)
            stage.rename(SOURCE)
    rustlib = SYSROOT / "lib/rustlib"
    rustlib.mkdir(parents=True, exist_ok=True)
    for name in (host, "etc"):
        destination = rustlib / name
        if not destination.exists(): destination.symlink_to(installed / "lib/rustlib" / name, target_is_directory=True)
    rustsrc = rustlib / "src"
    rustsrc.mkdir(exist_ok=True)
    destination = rustsrc / "rust"
    if not destination.exists(): destination.symlink_to(SOURCE, target_is_directory=True)
    apply_overlay()
    return SOURCE, SYSROOT

def apply_overlay():
    state_path = SOURCE / ".alix-overlay.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    updated = dict(state)

    def publish(relative, content, original=None):
        path = SOURCE / relative
        current = path.read_text() if path.exists() else None
        if current == content: return
        digest = hashlib.sha256(current.encode()).hexdigest() if current is not None else None
        if current is not None and current != original and state.get(relative) != digest:
            raise RuntimeError(f"Rust port source has unrelated edits: {relative}; left untouched")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        updated[relative] = hashlib.sha256(content.encode()).hexdigest()

    overlay = HERE / "overlay"
    for path in overlay.rglob("*.rs"):
        publish(str(path.relative_to(overlay)), path.read_text())
    patch_selectors(publish)
    state_path.write_text(json.dumps(updated, indent=2) + "\n")

def patch_selectors(publish):
    installed, _ = rust_info()
    pristine = installed / "lib/rustlib/src/rust"
    patches = {}

    def branch(relative, body):
        original = (pristine / relative).read_text()
        if "cfg_select! {" not in original: raise RuntimeError(f"missing selector in {relative}")
        patches[relative] = (original, original.replace("cfg_select! {", 'cfg_select! {\n    target_os = "alix" => {\n' + body + '\n    }', 1))

    base = "library/std/src/sys/"
    for path, body in {
        "pal/mod.rs": "        mod alix;\n        pub use self::alix::*;",
        "alloc/mod.rs": "        mod alix;",
        "stdio/mod.rs": "        mod alix;\n        pub use alix::*;",
        "thread/mod.rs": "        mod alix;\n        pub use alix::*;",
        "time/mod.rs": "        mod alix;\n        use alix as imp;",
        "io/error/mod.rs": "        mod alix;\n        pub use alix::*;",
        "random/mod.rs": "        mod alix;\n        pub use alix::fill_bytes;",
        "args/mod.rs": "        mod alix;\n        pub use alix::*;",
    }.items(): branch(base + path, body)
    # Reuse upstream concurrent algorithms, replacing only the OS wait boundary.
    for item, exports in {"mutex": "Mutex", "condvar": "Condvar", "once": "Once, OnceState",
                          "rwlock": "RwLock", "thread_parking": "Parker"}.items():
        branch(base + f"sync/{item}/mod.rs", f"        mod futex;\n        pub use futex::{{{exports}}};")
    relative = base + "args/mod.rs"
    original, changed = patches[relative]
    changed = changed.replace("#[cfg(any(\n", '#[cfg(any(\n    target_os = "alix",\n', 1)
    patches[relative] = original, changed
    relative = "library/std/build.rs"
    original = (pristine / relative).read_text()
    patches[relative] = original, original.replace('if target_os == "linux"', 'if target_os == "alix"\n        || target_os == "linux"', 1)
    relative = base + "exit.rs"
    original = (pristine / relative).read_text()
    changed = original.replace('pub fn exit(code: i32) -> ! {\n    cfg_select! {',
        'pub fn exit(code: i32) -> ! {\n    cfg_select! {\n        target_os = "alix" => { unsafe { crate::sys::ffi::exit(code) } }', 1)
    patches[relative] = original, changed
    relative = base + "env_consts.rs"
    original = (pristine / relative).read_text()
    native = '''#[cfg(target_os = "alix")]
pub mod os {
    pub const FAMILY: &str = "";
    pub const OS: &str = "alix";
    pub const DLL_PREFIX: &str = "lib";
    pub const DLL_SUFFIX: &str = ".so";
    pub const DLL_EXTENSION: &str = "so";
    pub const EXE_SUFFIX: &str = "";
    pub const EXE_EXTENSION: &str = "";
}
'''
    patches[relative] = original, original.replace("cfg_unordered! {", "cfg_unordered! {\n" + native, 1)
    relative = base + "thread_local/mod.rs"
    original = (pristine / relative).read_text()
    changed = original.replace('pub(crate) mod destructors {\n    cfg_select! {',
        'pub(crate) mod destructors {\n    cfg_select! {\n        target_os = "alix" => {\n            mod alix;\n            pub(super) use alix::register;\n        }', 1)
    # Use the generic key guard, whose callback runs Rust thread bookkeeping
    # after Alix's native C++-ABI destructor stack has been drained.
    changed = changed.replace('pub(crate) mod key {\n    cfg_select! {',
        'pub(crate) mod key {\n    cfg_select! {\n        target_os = "alix" => {\n            mod racy;\n            mod alix;\n            pub(super) use racy::LazyKey;\n            pub(super) use alix::{Key, get, set};\n            use alix::{create, destroy};\n        }', 1)
    patches[relative] = original, changed
    # The key guard invokes list::run on other platforms. Native Alix already
    # drains registered destructors through __cxa_thread_atexit_impl.
    relative = base + "thread_local/guard/key.rs"
    original = (pristine / relative).read_text()
    changed = original.replace('            destructors::run();', '            #[cfg(not(target_os = "alix"))]\n            destructors::run();')
    patches[relative] = original, changed
    for relative, (original, changed) in patches.items():
        publish(relative, changed, original)

if __name__ == "__main__":
    source, sysroot = prepare()
    print(f"Prepared matching Rust source: {source}\nIsolated sysroot: {sysroot}")
