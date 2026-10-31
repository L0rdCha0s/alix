# Native Rust standard library for Alix

`make zen-rust-runtime` rebuilds the real upstream Rust `core`, `alloc` and `std`
sources for the explicit `x86_64-unknown-alix` target, then links
`build/user/rust_std_test.elf` against Alix's CRT and libc. It does not select a
Linux target or replace `std` with a custom facade.

The compiler and source revision are pinned in `upstream.json`. Preparation
copies the installed matching `rust-src` component, including its vendored
dependencies, into `ports/zen/upstream/rust-1.97.1`; the installed toolchain is
never modified. Tracked files in `overlay/` implement the Alix OS boundary.
`prepare.py` applies target selectors only to source matching the pristine base
or its own recorded prior overlay. Unexpected local edits are preserved.

The target uses x86-64 ELF, a large code model, static relocation, SSE2,
local-exec ELF TLS and `panic=abort`. It has `target_os="alix"` and no fake
`target_os="linux"` or Unix-family selection. Cargo's unstable build-std and JSON
target support are enabled with `RUSTC_BOOTSTRAP=1` for this matching custom
standard-library build. No host library is linked into the native executable.
`rustc.py` translates the explicitly requested Alix target name to the pinned
JSON specification; it does not add a fabricated built-in to `--print target-list`.
Gecko must accept that declared custom specification and still run its genuine
Rust std compilation probe.

Source, Cargo caches, objects and isolated sysroot remain outside QEMU's
FAT-backed `build/` directory. Native `.rlib`/`.rmeta` files are published as an
immutable snapshot and selected by the isolated sysroot's target `lib` symlink.
The target standard libraries include LLVM bitcode, required when Gecko links
its Rust code with LTO. `build.py --no-publish-smoke` rebuilds and installs that
immutable standard-library snapshot while retaining the newly linked smoke ELF
in the source cache; it preserves the existing guest fixture during native QA.
The smoke package's build script tracks external native object, linker-script
and runtime-archive inputs explicitly. Cargo therefore relinks the executable
after libc changes instead of merely copying a binary linked against older
objects. The standard-library crates remain reusable when only those native
link inputs change.
Host metadata points to the matching installed compiler's host libraries solely
for build scripts. It is not used by the Alix executable.

Implemented native boundaries:

- `System` allocation uses Alix malloc/calloc/realloc/free/posix_memalign.
- Console IO uses real read/write syscalls; errors are not reported as writes.
- Clocks use native monotonic and wall-clock milliseconds.
- Thread startup transfers a heap-owned upstream `ThreadInit` object to the
  kernel and honors Rust's requested stack size (default 2 MiB).
- Native thread detach/join and exit run Alix TLS destruction.
- Upstream Rust mutex, condition-variable, rwlock, once and parker algorithms
  use Alix's process-private futex wait/wake interface.
- Rust native TLS destructors use `__cxa_thread_atexit_impl`; TSD keys schedule
  Rust thread cleanup after the native destructor stack.
- `args` copies CRT arguments to heap-owned storage before sharing them.
- `HashMap` keys use Alix `getrandom`; failed entropy is a real failure, with no
  deterministic substitute.

The initial native acceptance marker is `RUST_STD_TEST: PASS`, and checks actual
allocation/formatting, argument access, entropy-backed HashMap, time arithmetic,
eight CPU-bound threads, 1,024 synchronized updates, OnceLock and TLS destructors.
Only guest execution proves this gate. Compilation alone is insufficient.

Validated in an eight-CPU Alix guest on 2026-10-31:
`build/test-out/rust-std-qemu.log` contains
`RUST_STD_TEST: PASS workers=8 cpu_mask=0xFF count=1024 tls_dtors=8 hashmap=256`.
The native program contains one `println!`; the current kernel console tap plus
shell capture replay duplicates that line in serial output. That is an existing
stdio routing issue being addressed with per-process descriptors, not a second
Rust test run or a suppressed write.

The genuine direct compiler `println!` static-library probe also passed for the
declared custom target, and all its archive objects were verified as x86-64 ELF.
Builds include a source-derived fingerprint because Cargo otherwise treats
sysroot sources as immutable. Installation selects the exact artifacts emitted
by the current Cargo build instead of mixing older libraries from its cache.

This is still an incomplete platform port. Filesystem, network and process
creation remain the upstream unsupported implementations and return errors.
Environment handling beyond arguments, OS-level thread renaming, unwinding,
dynamic loading and Rust ecosystem crates with platform-specific dispatch still
need implementation. These limitations must not be described as full Rust std
or Zen completion.
