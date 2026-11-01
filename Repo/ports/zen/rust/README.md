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
- Thread startup transfers a heap-owned upstream `ThreadInit` object through
  native pthread creation and honors Rust's requested stack size (default 2 MiB).
- Join, detach and callback return use the real pthread registry and TLS cleanup.
- Builder names reach the native pthread naming API with its OS length limits.
- Upstream Rust mutex, condition-variable, rwlock, once and parker algorithms
  use Alix's process-private futex wait/wake interface.
- Rust native TLS destructors use `__cxa_thread_atexit_impl`; TSD keys schedule
  Rust thread cleanup after the native destructor stack.
- `args` copies CRT arguments to heap-owned storage before sharing them.
- `HashMap` keys use Alix `getrandom`; failed entropy is a real failure, with no
  deterministic substitute.
- `File` and `OpenOptions` use native owned descriptors for opening, reading,
  writing, shared-offset cloning, seeking, resizing, synchronization and metadata.
- `std::os::fd` retains upstream OwnedFd/BorrowedFd ownership and conversions;
  `std::io::pipe` uses native atomic CLOEXEC creation and descriptor cloning.
- Path metadata, symlink reads, canonicalization, directory iteration, exclusive
  directory creation, rename, unlink and empty-directory removal use checked
  libc calls. Directory entries copy their names before advancing the C stream.
- `std::os::alix::ffi` reuses upstream byte-string extensions, including arbitrary
  non-UTF-8 path bytes, without publishing a Unix target identity.
- Environment reads/enumeration use independent C snapshots captured under the
  same native mutex as C/Rust writers. Returned values and iterators own bytes.
- Native cwd changes/queries, colon-separated PATH splitting/joining, TMPDIR,
  HOME/account fallback and executable-path discovery use real Alix services.

The initial native acceptance marker is `RUST_STD_TEST: PASS`, and checks actual
allocation/formatting, argument access, entropy-backed HashMap, time arithmetic,
eight CPU-bound threads, 1,024 synchronized updates, OnceLock and TLS destructors.
Only guest execution proves this gate. Compilation alone is insufficient.

`build/test-out/rust-std-qemu.log` preserves the original acceptance marker
`RUST_STD_TEST: PASS workers=8 cpu_mask=0xFF count=1024 tls_dtors=8 hashmap=256`.
The current executable links the owned-descriptor profile and additionally
requires the thread-handle, filesystem and environment markers described below.

The genuine direct compiler `println!` static-library probe also passed for the
declared custom target, and all its archive objects were verified as x86-64 ELF.
Builds include a source-derived fingerprint because Cargo otherwise treats
sysroot sources as immutable. Installation selects the exact artifacts emitted
by the current Cargo build instead of mixing older libraries from its cache.

This is still an incomplete platform port. Filesystem locking, permission/time
changes, copy, link creation and recursive removal return Unsupported. The VFS
does not yet enforce Unix mode permissions, and status-change time is not
reported as a fabricated birth time. Network and process creation remain the
upstream unsupported implementations. Unwinding,
dynamic loading and Rust ecosystem crates with platform-specific dispatch still
need implementation. These limitations must not be described as full Rust std
or Zen completion.

`std::os::alix::thread::{JoinHandleExt, RawPthread}` exposes the actual 64-bit
pthread identifier without enabling a Unix/Linux target identity. Borrowed
`as_pthread_t()` handles remain owned by Rust; consuming `into_pthread_t()`
transfers responsibility for C pthread_join or pthread_detach to the caller.
The closure's Rust return value is dropped rather than returned as a C pointer.
Rust thread creation now uses pthread_create instead of bypassing its registry,
so transferred handles work with the native C APIs. ThreadInit, attributes and
publication storage are heap-owned; no worker retains a parent stack address.

`tests/rust_native_handles.rs` is part of the real std smoke executable. Eight
pinned workers compare exported handles to pthread_self(), check native names,
stack size and guard metadata, then join through Rust. Sixteen consuming C joins,
sixteen consuming C detaches and sixteen implicit detach operations check
ownership, result destruction and 56 TLS destructor runs. The original eight
threads, 1,024 updates, OnceLock, HashMap, time and TLS checks also still pass.
`make zen-rust-runtime-qemu-test` requires all four native markers and exit status 0.

`tests/rust_filesystem.rs` exercises the actual public upstream APIs in eight-CPU
Alix. It checks shared clone offsets, CLOEXEC, shrink/grow zero-fill, 64-bit seeks,
metadata, File/OwnedFd/raw-FD transfers and closing, borrowed descriptor clones,
real Rust pipes and EOF after Stdio ownership is dropped, byte-exact filenames,
copied directory entries and cwd/symlink-aware canonicalization. Eight pinned
threads synchronize before racing exclusive file/directory creation; exactly
one creator succeeds for each. They also write/read, append, rename and remove
independent files. The required marker is `RUST_FILESYSTEM_TEST: PASS`.
Production VFS host contracts separately check 1,024 strict mkdir attempts,
captured ownership, read-only parents and allocation-failure atomicity under
AddressSanitizer/UndefinedBehaviorSanitizer and ThreadSanitizer.

`tests/rust_environment.rs` requires `RUST_ENVIRONMENT_TEST: PASS`. Eight pinned
workers perform 1,536 C/Rust environment updates and 512 full snapshots, checking
owned values and complete shared-variable replies while other CPUs replace
them. Separate checks cover non-UTF-8 keys/values, invalid lookups, an iterator
snapshot surviving mutation of borrowed putenv storage, real cwd/symlink and
relative absolute-path behavior, PATH bytes/empty segments and TMPDIR/HOME
policy. `current_exe` uses `alix_get_executable_path`, which reports the loader's
immutable launch snapshot independently of cwd and argv. The std adapter copies every C-owned result
before freeing it and never retains a mutable getenv pointer after unlocking.

Home fallback calls native getpwuid_r for the current uid. Its heap-owned
metadata/read/parse work understands Alix's actual account format and publishes
only caller-owned strings. Missing users return no record instead of root's
home. Relative account homes resolve from the namespace root, matching login.
`tests/pwd_contract_test.py` checks production parsing, malformed/overflowing
ids, exact uid/name selection, caller storage, ERANGE without publication,
read failures/EINTR, allocation failures and 8,000 concurrent lookups under
ASan/UBSan and TSan. The real std guest checks C account lookup and fallback too.

The tracked Gecko style patch selects this Alix extension and its real C
pthread_t representation. The actual Gecko Rust root build emits a fresh
native style rlib/rmeta, including StyleThreadPool::get_thread_handles. This
does not prove a complete gkrust link or browser execution: the root build still
reports other crate-dispatch and loader gaps.

The tracked URL patch enables file-path conversion using the native byte-string
extensions. Rust's absolute-path selector also explicitly includes Alix; leaving
that selector unchanged made even `/tmp/file` appear relative despite the byte
path backend. The filesystem smoke now checks absolute and relative paths.
`make zen-rust-file-urls-qemu-test` sequentially rebuilds std, configures Gecko,
builds its actual vendored URL package using Gecko's manifest/lock/vendor tree,
then links and runs the native fixture. It checks spaces/reserved characters,
Unicode and invalid UTF-8 roundtrips, localhost, remote-host rejection, NUL
rejection at the file boundary and concurrent file readback from eight CPUs.
`build/test-out/rust-file-urls-qemu.log` contains `RUST_FILE_URLS_TEST: PASS`;
the compile/link receipt records the exact URL rlib, source and ELF hashes.
This is native component execution, not a complete gkrust or Zen link.

`make zen-rust-os-consumers-qemu-test` uses the configured Gecko Rust root
feature graph, because its Glean and storage packages are not all reachable
through the default dependency set. The native Glean, kvstore, errno and
processtools libraries now compile. The acceptance executable invokes the
actual Glean public `glean_enable_logging_to_fd` API and actual errno crate;
it includes kvstore's private path module directly from the patched source.
Eight pinned threads deliver 256 JSON log records through a native pipe,
including Unicode, escaped newlines and quotes. A concurrent reader checks
every record exactly once. Threads also check distinct C errno addresses,
isolation across yields, errno from real failed opens, native error formatting
and storage canonicalization/readback. Invalid UTF-16, NUL, empty and overlong
paths report errors. C header comparisons verify errno and signal constants;
native kill probes check the current pid, a nonexistent pid and an invalid
signal. They do not initialize the XPCOM process service or create processes.

The tracked selectors reuse upstream portable descriptor ownership and the
upstream errno implementation with Alix's actual POSIX strerror_r signature
and __errno_location symbol. Native libc declarations follow Alix headers;
no Unix family is enabled. Storage canonicalization uses the native std adapter
that copies and frees realpath's allocation through the same C allocator.

`gecko_fixture.py` shares native Cargo setup, exact hashed artifact selection,
link validation and receipts between the URL and OS-consumer gates. The latter
records the full root's exit 101 and failed packages explicitly, and requires
every requested native component artifact before linking its guest executable.
It does not turn a failed root build into a successful browser build. Current
root errors after directory discovery are in mtu, socket2, ash, rustix and wr_glyph_rasterizer.
The required guest marker is `RUST_OS_CONSUMERS_TEST: PASS`.

`make zen-rust-directories-qemu-test` builds Gecko's actual dirs and dirs-sys
crates in the same configured root graph. Eight pinned guest workers parse real
XDG user-dirs.dirs files and check HOME expansion, disabled/relative entries,
quotes, backslashes, Unicode and invalid UTF-8 bytes. Separate checks cover
account fallback, default config/cache/data/state/bin/font paths, absolute XDG
overrides and rejection of relative overrides. The runtime-directory API
returns the configured location without implicitly creating it. C/Rust checks
also compare the passwd size/field offset and invoke both reentrant lookups.
`build/test-out/rust-directories-qemu.log` contains `RUST_DIRECTORIES_TEST: PASS`.
The build receipt preserves the broader root's exit 101 and five failing
packages; native directory execution is a separate, successful gate.
