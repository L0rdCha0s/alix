# Native Zen Browser port

## Direction and current status

The new browser uses **Zen's Firefox/Gecko/SpiderMonkey stack** for HTML, CSS,
layout, JavaScript and browser chrome. Alix supplies the operating-system and
window-system interfaces. The existing `user/lib/web` and `atk_html_view` engine
is not part of the new port.

**Zen does not build or run on Alix yet.** The pinned standalone SpiderMonkey
configuration and full static-shell build succeed for `x86_64-unknown-alix`.
The real shell runs inside eight-CPU Alix, including observed Ion JIT execution,
eight GC cycles with 10,000 rooted objects, WebAssembly execution/bounds trapping
and worker shared Atomics. Gecko configures in a separate native object tree
with `widget/alix` selected. The complete widget, NSS and browser runtime
still require compile and runtime acceptance.

The thirteenth full build completes Gecko's entire configured Rust root in
19m03s and produces a fresh 1,196,948,572-byte `libgkrust.a`. Cross objdump
identifies all eleven archive members as native x86-64 ELF. The archive hash,
compiler target, Rust snapshot and build-log hash are recorded in
`build/ports/zen/gkrust-native-build.json`. The remaining C++ build exposed a
missing `sleep` API in `ContentChild.cpp`; shared Alix libc now implements it,
with host sanitizer and eight-CPU guest checks. The complete Gecko application
has not linked, and Zen has not launched.

Native prerequisites now include LLVM libc++/libc++abi file streams, upstream
Rust `std` threading/synchronization, executable-path discovery, borrowed-storage
`putenv`, private semaphores, shared descriptor flags, cubeb/Speex playback and
software window presentation. WASI sandbox compiler/header/link probes pass.
These results establish individual OS boundaries; the full Rust filesystem,
network and process backends remain incomplete.

The earlier seventh keep-going build finished with compile errors after 21:14.
It clears the earlier resolver/select and C++ style-handle declarations and
reaches Rust style compilation. Its diagnostics are preserved as
`build/ports/zen/gecko-seventh-compile-diagnostics.log`. Dynamic loading,
NSPR/system interfaces, shared memory/local IPC and Rust platform dispatch
were incomplete at that checkpoint. This was not a successful browser build.

Follow-up work now also clears the Rust style thread-handle errors. The real
upstream std uses Alix pthread creation, join/detach and OS naming, with native
borrowed/consuming handle extensions. Guest checks cover eight CPU-pinned native
identities, names and stack metadata, 48 ownership-transfer/drop cases and 56
TLS destructor runs. The existing std synchronization/HashMap/time regression
still passes. The actual Gecko Rust root build then produces a fresh native
style library containing get_thread_handles. At that checkpoint the broader
root failed on other platform gaps. The thirteenth build now completes the
Rust root; the application link remains unverified.

File resizing, VFS canonical paths and atomic directory-only removal now pass
eight-CPU native tests and the actual Rust libc ABI fixture. Shrink/grow
zero-fill also survives fsync and a second AlixFS boot. NSPR's actual uxshm.c
source now compiles after ftruncate is added. Upstream Rust File/OwnedFd now
uses these native services and passes eight-CPU guest tests for cloning/shared
offsets, resizing, synchronization, metadata, paths, directory iteration,
exclusive creation and ownership transfer. Native Rust pipes, cloned ends and
Stdio-drop EOF also pass. Byte-range fcntl locking, permission/time changes, copying, link
creation and recursive removal remain unsupported; shared mappings remain
unfinished.

Gecko's actual vendored URL crate now converts native file paths in an
eight-CPU Alix guest. Its real parser roundtrips spaces/reserved characters,
Unicode and non-UTF-8 bytes, then reads files through decoded URLs. The test
also caught and fixed Rust's absolute-path selector omitting Alix. Remote file
hosts are rejected and decoded NUL bytes fail at the filesystem boundary.
This component acceptance does not establish a complete Gecko Rust link.

The configured Gecko Rust graph now also emits native Glean, kvstore, errno
and processtools libraries alongside style, rkv and sql-support. Glean's public
logging API passes 256 JSON records through a native pipe from eight pinned
CPUs. Its real errno crate shares C's per-thread errno, preserves isolation
across scheduling and formats errors through native strerror_r. The actual
kvstore path module passes wide-path conversion, symlink-aware canonicalization
and error cases. C/Rust errno/signal ABI checks and kill identity/error probes
also pass; XPCOM process-service startup is not yet exercised.

Native Rust environment and path APIs now also pass eight-CPU execution:
1,536 synchronized C/Rust environment updates, 512 snapshots, byte-preserving
values, owned iterators, real cwd/executable discovery and exact-uid account
fallback. The reentrant libc account parser passes 8,000 concurrent host
lookups with ASan/UBSan and TSan. Gecko's actual dirs/dirs-sys crates then pass
eight-CPU tests for default/overridden locations and real XDG user-directory
files, including escaped and non-UTF-8 names.
The default account config path also supports recursive profile-directory
creation and preferences write/sync/readback without HOME/XDG overrides.

The earlier directories-component build exited 101 on mtu, socket2, ash,
rustix and wr_glyph_rasterizer. Historical diagnostics are in
`build/ports/zen/rust-directories-native-build.log`; the native component
receipt records that failed root result separately from the successful
component compile/link and guest execution. No complete application link is
claimed.

Outbound IPv4 TCP and its supported endpoint/options profile pass eight-CPU
packet-correlated tests. DNS/netdb passes controlled lookup, multiple A/CNAME
records, negative replies, reentrant/TLS callers, resolved TCP and killed-caller
recovery. The actual Gecko-vendored Rust libc passes the native socket and
address-lookup ABI tests. See [sockets](kernel/sockets.md) and
[resolver](kernel/resolver.md) for the remaining IPv6/UDP/local-IPC and resolver
limits.

`fsync`, checked `MADV_WILLNEED`, and physical-page `sysconf` queries now pass
native eight-CPU execution. A 64 KiB file and its metadata survive a stopped-VM
disk snapshot and a separate AlixFS remount boot. This test also exposed and
fixed AlixFS replacing the destination mount-point name with its old on-disk
root name; a disk written before the fix passes native readback too. Gecko's
actual `MemUtils.cpp` and `ggml-cpu.cpp` objects now compile with the new APIs.
These scoped compilations do not establish a complete Gecko link.

LLVM libc++'s actual `std::random_device` is now enabled with its existing
getentropy backend. Eight-CPU guest tests pass 4,096 samples, descriptor-table
exhaustion, unavailable entropy and invalid-token errors. Both failure paths
follow the existing no-exceptions abort policy; the QA fixture catches SIGABRT
only to verify the diagnostics. The original LLVM implementation is retained,
without a userspace substitute generator or /dev/urandom file. The actual
llama-sampler.cpp consumer now compiles, and the full existing libc++/libc++abi
thread/TLS/file/exit guest regression still passes.

Native `select` now passes eight-CPU descriptor/TCP, safe-copy, signal,
close/reuse and killed-caller checks, including exception-only hangup waits.
The actual vendored Rust libc passes fd_set/timeval layout and select calls.
NSPR's real prnetdb.c compiles using native reentrant host/protocol queries;
the native pthread include also lets the complete nsDeviceContext.cpp compile.
A refreshed compilation audit passes all 64 selected NSPR C sources, including
the shared file mapping and synchronous signal-wait paths.
These are individual source compilations, not an NSPR library
link or runtime result. See [poll/select](kernel/poll.md).

Native ioctl now supplies atomic nonblocking changes, readable-byte snapshots
and per-slot CLOEXEC controls. Eight-CPU pipe/file/TCP checks, legacy namespace
rejection and actual Gecko Rust libc ABI tests pass. Queries preserve offsets,
peeked bytes and pending socket errors. NSPR's configured Unix source advances
past sys/ioctl.h. See [descriptor controls](kernel/ioctl.md).

Native uname/hostname and primary-group/effective-identity getters now pass
eight-CPU tests, including 512 snapshots during 64 hostname replacements.
The version identifies the actual running kernel's ELF build ID, verified
against the private boot image. The configured NSPR metadata code also passes
native open-flag, 64-bit size and checked timestamp-conversion tests. Its
complete library now has separate native execution acceptance below. See
[system identity](kernel/system_identity.md) for ownership and validation scope.

NSPR's public random-noise, physical-memory and CPU-count functions also run
inside Alix. Its entropy backend uses native getentropy and returns at most
256 bytes per call, as permitted by NSPR's short-result contract. Failures
return zero with the native error mapped into NSPR; no clock data replaces
unavailable entropy. Guest tests cover 512 samples across eight pinned CPUs,
descriptor exhaustion, buffer protection and a separate CPU configuration
without RDRAND. The fixture links whole upstream resource/error-mapping
objects, instruments the per-thread error sink and disables SSP only for
this component test so the unavailable-entropy case can reach main.
Production compiler flags and SSP startup remain unchanged; complete NSPR
initialization is still unverified.

Native synchronous file writes now pass eight-CPU execution and independent
AlixFS remount readback: 64 append writes retain all 32 KiB without an explicit
fsync. The shared sync flag survives aliases, F_SETFL and partial ioctl changes;
failed flushes report EIO and the legacy namespace rejects sync before mutation.
Gecko's actual Rust libc checks the native 64-bit open ABI and synchronous
calls. NSPR's poll/select/nonblocking selectors now use the existing native
interfaces, and its actual nonblocking helper preserves O_SYNC. See
[synchronous files](kernel/synchronous_files.md).
Enforced descriptor limits now pass 512 operations on eight pinned CPUs,
including atomic pipes, sockets, preservation of high descriptors and failed
truncation, checked metadata copies and spawn inheritance/isolation. Host
ASan/UBSan and TSan checks pass 8,000 concurrent operations. The actual Rust
libc fixture checks its native resource ABI and enforced open failure. NSPR's
complete pthread I/O source now compiles, and its table-size entry points run
against the native FD policy. Its multicast request structure is declared;
multicast operations remain unsupported. Full NSPR initialization now passes
the library suite below. See [descriptor limits](kernel/descriptor_limits.md).

NSPR's native launch helper now uses Alix posix_spawn with an owned environment
snapshot, redirected standard descriptors and child-only cwd actions. Its actual
code passes 25 child launches with eight pinned callers, crossed stdio, CLOEXEC,
environment variants, constructor-time cwd/environment, failure restoration and
descriptor cleanup. The kernel cwd action separately passes 24 concurrent child
launches with ordered relative opens, relative executable/PATH lookup and parent
isolation. ASan/UBSan checks fault each helper preparation step and validate cwd
ownership/error cleanup. The complete upstream process source compiles; full
NSPR initialization and its actual wait daemon now pass the full-library
parent/child fixture as well. See
[child processes](kernel/child_processes.md).

Real native ELF dynamic loading now passes five eight-CPU guests: C/C++ shared
objects execute with libc imports, dependencies, global/local lookup, GNU hashes,
packed relocations, constructors/finalizers and 512 isolated TLS updates.
Pending C++ destructors retain their code after dlclose; process exit finalizes
libraries while keeping code mapped for terminating threads. RELRO and code
write attempts fault as intended. ASan/UBSan fault injection and 3,000 metadata
mutations pass, as does the existing upstream libc++/libc++abi regression.
NSPR's linking, allocator and pthread sources now compile. Startup dependency loading,
additional dynamic ABI forms and Zen remain incomplete. See
[dynamic loading](kernel/dynamic_loading.md).

Native `sigwait` now passes 512 directed waits across eight CPUs, competing
process waiters, protected/cross-page output failures, signal coalescing,
unrelated-signal retry, waiting inside a handler and killed-waiter cleanup.
The kernel captures the input mask and retains only thread-owned wait state;
failed checked output does not consume a pending signal. Actual Gecko Rust libc
bindings pass native mask/block/raise/wait/restoration checks as well. Plain and
ASan/UBSan host tests pass 201 signal assertions. See [signals](kernel/signals.md).
The real unified NSPR 4.40 library now links and runs in Alix. Its full-library
suite passes initialization, eight threads and 512 synchronized updates, once,
conditions, TLS destructors, environment snapshots, real TCP gather writes,
pipes/pollable events, shared file maps, child startup/wait-daemon status and
cleanup. Native executable exports supply the canonical C runtime and SSP guard;
missing strong imports still fail at load. Unsupported network operations report
their error paths. See [NSPR runtime](kernel/nspr_runtime.md) for exact scope and
the canonical current build log. This is still separate from Gecko/Zen startup.

Gecko's actual `libloading` and `ash` Rust crates now have explicit Alix ELF
dispatch without selecting a foreign OS family. A native eight-CPU consumer
passes code loading, constructor/finalizer imports, 512 independent TLS updates,
defined NULL symbols, missing-library/symbol errors, main-executable lookup and
unload. Ash's absent-Vulkan-library path reports its normal loading error; this
does not establish a Vulkan backend. These targeted crate checks are separate
from the complete Rust archive build recorded above and from browser startup.

Upstream Rust `std::net` now uses native Alix TCP descriptors, including safe
owned-FD conversions. Its eight-CPU guest passes nine connections, 294,912
payload bytes, connect deadlines/refusal, cloning, CLOEXEC/nonblocking status,
peek/EOF, lookup and hostname. The broader network capabilities remain separate
porting work.

WebRender's actual FreeType rasterizer now runs in eight-CPU Alix using Gecko's
bundled C library. It passes 512 concurrent glyph renders, monochrome/alpha/
subpixel modes, variable-font weight changes and matching raw/file pixels
through non-UTF-8 paths. The real C objects exposed main executable GOT imports;
the CRT and upstream validator now handle that relocation form with checked
symbols, destinations and TLS addends. See [glyph rasterization](kernel/glyph_rasterization.md).
This establishes the rasterizer backend, not a completed Gecko font platform,
compositor or Zen application.

The actual Socket2 crate now also compiles with its `all` feature and runs in
eight-CPU Alix. Its nine TCP connections transfer 294,912 bytes using native
polling deadlines, atomic CLOEXEC/nonblocking creation, cloned/shared status,
safe FD ownership, peek/EOF and real gather/scatter `sendmsg`/`recvmsg`.
The message API captures all vectors before sending and keeps metadata in the
registered request during waits; fault/cancellation/SIGPIPE contracts and
native bad-vector checks pass. Addressed and ancillary messages remain work.

Gecko's `mtu` crate now queries Alix's real route/interface/MTU service. Native
acceptance covers 512 queries on eight CPUs, checked copying and C/Rust ABI.
Host sanitizer checks cover 56,000 snapshots during 8,000 configuration changes.
See [native routes](kernel/network_routes.md).

A source audit found Gecko's direct Rustix use is confined to its
`target_vendor = "apple"` QUIC capability probe. Its Cargo dependency now has
that same condition. This removes an unused native dependency rather than
claiming a completed generic Alix Rustix filesystem/network backend. Host
build dependencies continue to use their normal Rustix implementation.
These component milestones are separate from the complete Gecko Rust archive
build; the application link and Zen startup remain unverified.

The ninth full build advances to Quinn's missing Alix UDP backend and C API gaps
in RLBox/SQLite. Its diagnostics are preserved in
`build/ports/zen/gecko-ninth-full-build.log`; the run was deliberately interrupted
after collecting those failures before editing compiler inputs.
Follow-up work clears the RLBox memory/clock compile failures in targeted
production builds. The actual runtime then passes eight-CPU execution with four
clocks, sampled CPU accounting, 8 GiB alignment, minimum-WASI imports, eight
independent WABT traps and a separate hardware guard fault. Alix now exposes
process/thread CPU clocks, clock resolution and the native page-size getter.
See [Wasm sandbox runtime](kernel/wasm_sandbox.md). SQLite's file-identity and
fchown compile gaps are now cleared. Versioned stat records preserve the old
40-byte ABI while adding device/inode/link identity and credentials for new
C/Rust consumers. Native eight-CPU snapshots and independent ownership/mode
readback pass. Basic fchmod, utimes and process-owned fcntl byte-range locks now
pass in Alix, including the actual Rust libc bindings. The configured SQLite
3.53.4 shared library now compiles and runs on eight CPUs: rollback, WAL snapshot
isolation, separate-process busy/commit behavior, concurrent writers, integrity
checks and 198 rows read back after an independent boot all pass. Its acceptance
is `build/test-out/sqlite-runtime.acceptance.json`. This loads Gecko's configured
libmozsqlite3.so, including FTS5/vector extensions, without changing build features.

The earlier full-library build exposed unsupported ELF symbol versions.
Native loader/validator support now checks definitions, requirements and aliases,
and the real library passes. The original rejected artifact/report remain under
`build/ports/zen/sqlite-versioning` as historical diagnostics. Versioned provider
and consumer fixtures also pass on eight CPUs, including missing requirements,
data, TLS and unload. See [dynamic loading](kernel/dynamic_loading.md#symbol-versions).

The tenth full build cleared the earlier Quinn platform error and exposed
Neqo UDP's Unix-only SocketRef selector. Patch `0041` selects the explicit Alix
FD traits/error codes and dependency. The actual Neqo wrapper now exchanges 128
datagrams across eight CPUs through Quinn, with packet-verified endpoints,
ECN/checksums and proper PMTUD error handling. This is transport acceptance;
complete HTTP/3 and Zen startup remain separate.

The eleventh build compiled Neqo UDP and reached Gecko's `neqo_glue`, where
two more Unix-only selectors omitted Alix's borrowed socket handle. Patch
`0042` selects the native `BorrowedFd` alias and initializer. The Neqo guest
fixture now uses borrowed descriptors, repeats the 128 packet-verified exchanges
on eight CPUs, and verifies that dropping the wrapper leaves its socket owner
open. The full Gecko build is being rerun with this glue fix.

The twelfth build produced the Neqo glue library and advanced through DOM
compilation, then exposed two Unix-only path-trait imports in WebRender's
Gecko bindings. Patch `0043` selects Alix's existing `OsStringExt`/`OsStrExt`
traits there. The font descriptor and Moz2D conversions retain their native
byte-preserving behavior; complete binding compilation and browser startup
still need verification.

The fourteenth full build completes Rust with the updated libc inputs, then
reaches Cairo's PDF sources. The native toolkit was missing from the
`MOZ_PDF_PRINTING` selector, leaving PDF and font-subset declarations disabled.
The platform patch now enables that backend for Alix. After regenerating the
export tier, the complete Cairo directory compiles; the PDF and font-subset
objects are native x86-64 ELF and contain the PDF creation entry points.
`build/ports/zen/cairo-pdf-native-build.json` records this compile evidence.
Native PDF output and the browser printing workflow remain unverified.

The fifteenth build reaches the graphics and IPC layers. The next platform
patch selects Skia's POSIX semaphore/file backend, exports the native FreeType
types and preferences, and supplies the generic compositor resize message.
The complete Skia, Moz2D, WebRender C++ bridge and headless directories now
compile. Shared libc/kernel support now also provides `MAP_NORESERVE` and
volatile `shm_open`/`shm_unlink` objects. Native checks cover an 8 GiB sparse
reservation, 512 shared updates across eight CPUs, read-only inherited handles,
unlink/recreate lifetime, killed creators and a namespace reset across reboot.
See [named memory](kernel/shared_memory.md). Process launch/wait integration,
the libevent platform configuration, layout selection and random-number APIs
remain the next diagnosed compile gates. There is still no complete browser
link or Zen runtime acceptance.
See [VFS identity](kernel/vfs.md#file-identity-and-ownership).

Native IPv4 UDP transport now passes an eight-CPU kernel acceptance workload:
256 outgoing datagrams and 256 real host replies, zero/odd/max-MTU payloads,
peek/truncation, retained ownership and shared DNS/NTP port leases. Independent
capture checks pass for checksums, ECN/TOS, TTL/DF, lengths and endpoints. The
ordinary kernel is restored after the fixture and the existing native DNS/netdb
regression passes. The userspace executor/API bridge and actual Quinn adapter
now also pass eight-CPU Alix execution with 256 host exchanges, Rust std
UdpSocket and the public C socket API. Packet captures verify ECN/source
selection and endpoint metadata. Killing a blocked receive caller releases its
port while unrelated sockets continue progressing. IPv6, multicast, offload and
POSIX addressed/ancillary message I/O remain unsupported. See
[UDP transport](kernel/udp_transport.md).

Regular-file shared mappings now pass eight-CPU aliases, 512 atomic updates,
independent spawned processes, killed-owner cleanup, FD close, private snapshots,
VFS coherence and partial protection/unmap tests. An independent AlixFS boot
reads 32,785 bytes persisted through `msync` without explicit `fsync`. Actual
Gecko Rust libc bindings and extracted NSPR map/sync/unmap functions pass as
components. The current backend rejects whole pages beyond EOF and shrinking
live mapped files; device/shared-anonymous mappings remain unsupported. See
[file mappings](kernel/file_mappings.md).

The existing browser remains available during the port.


## Source and reproducibility

`ports/zen/upstream.json` records Zen release **1.24b**, commit
`f75390aa2b797ddc3524ff9ed52ceb32a839f9fa`, whose `surfer.json` selects Firefox
**159.0**. The Firefox release commit is
`9a2dc53c369c7ae5172018b35988e1d2ffeff402`. The manifest also pins Mozilla's
source archive URL and SHA-512 from the official release checksum list.

```sh
make zen-fetch
make zen-fetch-engine
make zen-preflight
```

`zen-fetch` retrieves only that Zen commit, checks the release/base metadata and
license, and preserves an existing dirty or mismatched checkout by refusing to
overwrite it. It does not execute upstream scripts or install host dependencies.
The default source path is `ports/zen/upstream/desktop` (ignored by Git). Use
`ZEN_SOURCE_DIR=/path/on/a/larger/disk/desktop` to choose another checkout path.
Keep source trees **outside `build/`**, which QEMU exposes as its FAT boot disk.

`zen-fetch-engine` validates the pinned Firefox archive before extracting it to
`ports/zen/upstream/firefox-159.0`. The license remains in the source tree. An
existing source tree is compared with the verified archive; modified sources
are preserved and reported, never overwritten or silently certified as pristine.
Use `ZEN_ENGINE_DIR` and `ZEN_ENGINE_ARCHIVE` to choose another storage location.
Source acquisition does not apply the Zen overlay or implement an Alix backend.
Tracked Alix patches are applied separately by `make zen-patch-engine`. After
patching, `zen-fetch-engine` correctly reports the source as modified; use the
patch command to validate/reapply the recorded changes instead of resetting it.
The patch manifest records the pinned base and before/after file hashes, and
rejects unexpected edits without overwriting them. See
[`ports/zen/README.md`](../ports/zen/README.md) for the native build workflow.

`zen-preflight` reports source identity, free build space, available host tools
and actual C++ compilation diagnostics for Alix headers, pthreads, virtual
memory, dynamic loading, polling and C++ standard-library declarations. Logs go
to `build/ports/zen/preflight/`. It deliberately exits unsuccessfully while the
full native port is incomplete. Its baseline header probes are not the
authoritative upstream build result. A compiling declaration is not proof of ABI,
linking or runtime correctness. It never falls back to building a macOS/Linux
browser and calls that an Alix port.

The upstream guide requires at least 30 GB free for a build. `zen-preflight`
checks current availability before a future Firefox/toolchain bootstrap. The
small Zen checkout alone does not include that engine or toolchain. Do not
remove existing project files or VM data to make room automatically.

## Integration boundary

The Makefile now has separate `USER_WEB_OBJECTS` and `USER_HTML_VIEW_OBJECTS`.
Only the existing `atk_browser.elf` links them. `USER_COMMON_OBJECTS` and
`USER_ATK_OBJECTS` contain the ordinary application/runtime and ATK components.
`make user-engine-isolation-test` verifies the linked symbol boundary for all
packaged applications and checks that the old browser retains its engine.

Gecko needs a native widget/backend integration. Alix's `sys_ui_create`,
`sys_ui_present`, `sys_ui_poll_event`, and `sys_ui_close` are the initial
window-system boundary. Software pixels are 32-bit `0xFFRRGGBB` (BGRA byte order
on x86-64), as defined by `include/video.h` and `user/lib/video_surface.c`.
The backend must own each window and surface on the heap and synchronize render
workers explicitly. `video_surface.c` has one global active surface; it is not
a concurrent multi-window compositor. Alix ATK is unrelated to the GNOME ATK
accessibility library that desktop Linux builds may expect.

The raw native window API now also supports client move/resize, visibility,
focus, title changes, decorations, display queries and focus/move events.
These controls pass eight-CPU native state/concurrency/ownership checks and
actual compositor pixel validation for two independent surfaces; they do not
use the global userland video surface. See
[`kernel/windows.md`](kernel/windows.md). A tracked Gecko adapter now uses this boundary; its full compile/runtime
validation is pending. Native UI test surfaces are not Gecko or Zen rendering proof.

All browser engine work remains in userspace. libc additions belong in Alix
libc, not private substitute functions inside the browser application. Do not
pass pointers to one thread's stack to another thread or asynchronous callback.

## Implemented platform support and limits

- **C/C++ startup and lifetime.** Public application/runtime headers are C++
  compatible. CRT dispatches preinit/init arrays and routes normal termination
  through real exit/C++ finalization and reverse fini dispatch. Alix libc owns
  allocation, numeric conversion, clocks, once/TSD and exit callbacks. Native
  tests cover constructor order, over-aligned allocation, destructor
  repopulation, concurrent exit and thread-local destruction.
- **Upstream C++ runtime.** LLVM 22.1.8 libc++ and libc++abi are built as native
  x86-64 ELF archives against Alix headers/libc, with a native external-thread
  adapter. Eight-CPU guest tests exercise containers, strings, clocks,
  mutexes/conditions, `std::thread` and compiler-generated TLS destructors.
  This profile enables RTTI, threads, C/POSIX locale facets, narrow/wide streams
  and 16-bit wide characters. Native stream tests include 80-bit numeric
  roundtrips and all wide-character masks. LLVM file streams now pass binary
  read/write, append, 64-bit positioning and missing-file checks from eight
  concurrent native threads. A small tracked vendor patch enables file streams
  independently of optional `std::filesystem` operations. Exceptions, filesystem,
  Unicode-specific C++ formatting and terminal facilities remain
  disabled; ICU's own Unicode/locale support is independent and remains enabled.
  Shared-library unloading is not implemented. See
  [`ports/zen/libcxx/README.md`](../ports/zen/libcxx/README.md).
- **Upstream Rust runtime.** Rust 1.97.1 `core`, `alloc` and `std` are rebuilt
  for the explicit custom Alix target with a native platform layer. Allocation,
  console IO, arguments, time, futex-based synchronization, threads, TLS cleanup
  and entropy-backed `HashMap` have guest evidence. The target uses static
  relocation, local-exec TLS and `panic=abort`; it does not pretend to be Linux
  or a built-in Rust target. Native file/descriptor, directory, path and pipe
  APIs also have eight-CPU guest evidence. Whole-file advisory locks also pass
  native C/Rust tests with duplicate/inherited ownership, cancellation, close
  and process-exit cleanup. Byte-range fcntl locking, permission/time
  changes, copying, link creation and recursive deletion remain unsupported,
  as do network and process-creation backends. Native environment snapshots,
  cwd changes, executable discovery, HOME/account fallback and PATH handling
  now pass eight-CPU guest checks. Unwinding and ecosystem platform dispatch,
  including Rust integration with the new native dynamic loader, need further work. See
  [`ports/zen/rust/README.md`](../ports/zen/rust/README.md).
- **ELF TLS and threads.** The static `ET_EXEC` loader initializes `PT_TLS`
  data/BSS with alignment for the initial and created threads. FS points to the
  native thread-control block; compiler-generated TLS and `errno` are private
  per thread. Join/detach, CPU affinity, monotonic time, futexes, blocking mutexes,
  conditions and initial-thread/last-thread exit handling are implemented.
  Stack/TLS address holes are reused after safe reclamation. The new pthread
  facade adds full pointer returns, attributes, names, mutex kinds, condition
  clocks, once and keys; its normal and initial-thread-exit guest modes passed.
  Process-shared/robust synchronization, cancellation and caller-provided stacks
  remain unsupported. See [`kernel/pthreads.md`](kernel/pthreads.md).
- **Virtual memory and user copies.** Anonymous private `mmap`, `mprotect`,
  `munmap`, fixed replacement and sparse `PROT_NONE` reservations are implemented.
  Transactions retain replaced backing until cross-CPU TLB acknowledgement;
  failure preserves the prior mapping. Safe syscall copies resolve owned backing
  and permissions under the memory lock. Guest tests cover partial protection,
  fixed replacement, RW-to-RX and RWX generated code, concurrent access and fatal
  hardware permission faults. The new `MADV_DONTNEED` path discards backing and
  refills zero pages on permitted instruction faults or syscall copies;
  `posix_madvise` preserves contents. Native discard/refill and write-protection
  tests passed; the remaining fault-mode QA is recorded below. Regular-file
  shared/private mappings now have separate acceptance; shared anonymous
  mappings remain unsupported. The expanded user window runs from
  4 GiB to 64 TiB, with a 16 GiB brk reservation and a separate anonymous-VM
  arena. A native 32 MiB ELF and sparse 12 GiB mapping across high PML4 entries
  passed on eight CPUs. Committed memory remains limited by physical RAM, and
  the ELF loader still requires whole-file loading and contiguous segment
  backing. See [`kernel/memory.md`](kernel/memory.md).
- **Entropy and stack protection.** Native `getrandom`/`getentropy` use checked
  RDRAND output with bounded retries and real failure on unsupported hardware.
  Eight-CPU and unsupported-CPU guests passed. The optional compiler
  stack-protector archive initializes its guard from entropy before ordinary
  preinit/constructors and terminates on failure. Compiler/link checks and all
  four native guest modes passed, including the actual instrumented corruption
  epilogue and entropy-free CPU behavior. See
  [`kernel/entropy.md`](kernel/entropy.md) and
  [`kernel/stack_protector.md`](kernel/stack_protector.md).

## Upstream build and remaining acceptance gates

The native Clang driver uses Alix headers, CRT/linker script, LLVM
libc++/libc++abi and a real native Rust standard library. The pinned upstream
standalone SpiderMonkey build now passes its full default build and final link.
The Alix ELF check validates fixed executables, optional export metadata,
supported main TLS fixups and native shared-object relocations. The proven
standalone shell has no unresolved symbols or host runtime interpreter. See [`ports/zen/README.md`](../ports/zen/README.md)
for the patch manifest, build evidence and exact native execution boundary.

The complete C11 runtime includes the `nearbyint` family and full real/complex
math implementation. These underlying C/math functions are dependencies of
LLVM's C++ standard library, not supplied by adopting libc++ alone. The current
runtime reuses pinned musl and FreeBSD sources. Native C++/math, abort-hook,
streams, pthread/TLS, signal, VM and descriptor fixtures have separate acceptance.

Native child launch and waiting now support `posix_spawn`/`posix_spawnp`, copied
environment visible to constructors, ordered file actions, PATH search and
signal attributes. Eight-CPU fixtures and host sanitizers pass. Upstream shell
and Wasm-worker paths use these native interfaces instead of requiring fork/exec.
A native `sh` command executable is still needed by `os.spawn`; `fork` and
in-place `exec` remain unimplemented. See
[`kernel/child_processes.md`](kernel/child_processes.md).

The native shell passes both its basic script and full runtime smoke run with
normal exit status 0 in eight-CPU Alix. The latter observes Ion JIT execution,
roots surviving eight GC cycles, a Wasm function returning 42, a real Wasm
memory-bounds trap and a worker using shared Atomics. Fixes included libc++'s
16-bit wchar configuration, heap-owned multi-byte stdio pushback for BOM
lookahead, and a freeable zero-element `calloc` policy. The last fix supports
empty Wasm metadata arrays; the earlier error was not physical-memory exhaustion.
Native and host sanitizer regressions cover the changed libc behaviors. Temporary
Wasm compiler diagnostics have been removed and the clean engine rerun passes.

The test transfers a debug-stripped image whose load/TLS segments exactly match
the upstream binary, requires encoded/independently loaded script markers and
checks normal process status. Evidence is
`build/test-out/spidermonkey-basic-qemu.log` and
`build/test-out/spidermonkey-runtime-qemu.log`. This is standalone engine progress;
`build/ports/zen/spidermonkey-native.acceptance.json` ties the verified smoke
features to the executable hashes. This is not a complete upstream conformance
suite; `os.spawn` still needs `sh`, and Wasm subprocess serialization has not been
verified. Gecko and the full Zen browser remain unverified.

The remaining acceptance order is:

1. Build the full Gecko application and its NSPR/NSS/Rust dependencies with
   `make zen-gecko-configure` and `make zen-gecko-build`. It uses native
   `x86_64-unknown-alix`, `cairo-alix` and `obj-gecko-alix`; the standalone
   SpiderMonkey build and compiler-cache state remain separate. The current
   configure stage now completes. The native widget source, application-shell
   wakeups, screen metadata and software target upload are selected. The first
   full build reaches Rust and browser code, reporting remaining native libc,
   POSIX socket and further platform interface gaps. Native executable discovery,
   LLVM file streams and initial Rust libc bindings now have guest evidence;
   the seventh diagnostic pass clears resolver/select declarations, and later
   component builds clear style thread handles and native file URLs. Other
   native platform failures remain. Cubeb uses Alix's
   owned PCM channel and sandbox probes use the pinned WASI SDK. NSPR/NSS and the
   widget implementation still require complete compile/runtime acceptance.
2. Complete the OS interfaces demanded by Gecko, NSPR/NSS and Rust dependencies.
   The upstream runtime uses a private 256-slot table with owned descriptions,
   dup/shared offsets, imported stdio and protected blocking-I/O cleanup;
   installed legacy applications retain the original global table. Native
   callback VFS nodes and shell redirection remain acceptance
   gates. Extend the tested Rust filesystem/descriptor backends to the remaining
   required operations and ecosystem selectors. General userspace
   process creation, IPC, shared memory, dynamic loading, and the
   required POSIX filesystem/network surface remain unfinished. Existing socket
   syscalls are custom TCP/IPv4 interfaces; native DNS/TLS code alone does not
   establish Gecko/NSS integration.
   Native `poll` and `select` now pass pipes, regular files, TCP data/EOF, eight simultaneous
   CPU-pinned waiters, descriptor close/reuse, caught signals and killed-waiter
   cleanup. See [`kernel/poll.md`](kernel/poll.md) for scope and ownership.
3. Implement Gecko widget/event-loop/software composition in Alix windows.
   Extend input for scrolling, focus, text composition and clipboard as needed;
   current events cover mouse/key/resize/close. Prove upstream HTML/CSS layout,
   script execution, input and resizing in the guest.
4. Apply the pinned Zen overlay to the working Gecko platform and verify
   navigation, HTTPS, tabs, profiles, downloads, fonts and browser lifecycle in
   QEMU. Package a real native ELF and switch the default browser only after
   these tests pass.

Zen import preparation has separate receipts under `build/ports/zen`.
`zen-overlay-composition-preflight.json` records all 273 source patches
composing with the 49 Alix patches preserved. `zen-release-preferences/receipt.json`
records repeatable output from the pinned release preference generator.
`zen-release-resources/receipt.json` records the pinned search-settings merge
and 571 localization overlays across 42 locales, all parsed by Gecko's Fluent
parser. `zen-branding-project/receipt.json` records 80 repeatable release-branding
files generated by pinned Surfer 1.14.9, including nine verified native PNG icon
sizes and valid English Fluent branding. These files are staged outside the
active engine. Non-English Gecko locale baselines and the actual Zen import
remain separate work; these preparation receipts do not establish a running
Zen application.

Changing user address-space boundaries requires coordinated changes to
`src/arch/x86/uefi.ld` and `user/lib/link.ld`.

## Validation commands

Source preparation and the real upstream build are opt-in; ordinary `make`
does not fetch or compile the large upstream trees:

```sh
make zen-source-test                 # Offline fetch/pin/preservation tests
make zen-fetch                       # Real pinned upstream source verification
make zen-fetch-engine                # SHA-512-verified Firefox source extraction
make zen-fetch-cxx zen-cxx-runtime    # Pinned upstream LLVM runtime + native ELF
make zen-rust-runtime                # Pinned upstream Rust std + native ELF
make zen-host-tools                  # Locally pinned host cbindgen
make zen-patch-engine                # Validate/apply tracked Alix engine patches
make zen-patch-test zen-toolchain-test zen-ssp-test
make zen-js-build                    # Actual configure followed by mach build
```

Host contracts, normal integration and native guest acceptance are separate:

```sh
make libc-support-host-test pthread-contract-test
make futex-contract-test vm-reclamation-test native-vm-contract-test
make user-copy-contract-test auxiliary-pool-test entropy-contract-test
make process-pid-contract-test libcxx-threading-contract-test
python3 tests/stack_protector_contract_test.py
python3 tests/alix_getrandom_backend_test.py
make                                 # Required complete Alix build
make user-engine-isolation-test runtime-archive-test
make cpp-runtime-qemu-test            # Startup/ABI/destructor guest fixture
make zen-cxx-runtime-qemu-test         # Actual upstream libc++ in Alix
make zen-cxx-random-qemu-test          # RNG, descriptor pressure and failures
make zen-rust-runtime-qemu-test        # Actual upstream Rust std in Alix
make zen-gecko-os-interfaces-qemu-test # fsync/remount, advice and memory counts
make zen-select-qemu-test              # Owned selection, signals, TCP and cleanup
make zen-filesystem-primitives-qemu-test # Resize, canonical paths and empty dirs
make zen-flock-qemu-test            # Whole-file locks, aliases, cancellation and exit
make zen-ioctl-qemu-test            # Native descriptor controls and legacy rejection
make zen-system-identity-qemu-test  # Kernel build ID, hostname and credentials
make zen-nspr-file-abi-qemu-test    # Configured NSPR metadata/open ABI component
make zen-nspr-resources-qemu-test   # Real NSPR resource APIs and unavailable entropy
make zen-synchronous-file-qemu-test # Native O_SYNC and independent disk remount
make zen-fd-limits-qemu-test        # Enforced FD quotas, inheritance and legacy rejection
make zen-spawn-cwd-qemu-test        # Ordered child cwd actions and parent isolation
make zen-nspr-spawn-qemu-test       # Actual NSPR native launch helper
make zen-dynamic-loader-qemu-test   # Real ELF DSOs, dynamic TLS, lifetimes and permissions
make zen-sigwait-qemu-test          # Blocked signal acceptance and competing waiters
make zen-file-mapping-qemu-test     # Shared pages, private copies and msync remount
make zen-nspr-runtime-qemu-test     # Complete NSPR library public APIs in Alix
make zen-writev-qemu-test           # Gather capture, atomic pipes and append
make zen-rust-dynamic-loading-qemu-test # Actual libloading/ash and native DSOs
make zen-rust-std-net-qemu-test # Actual std TCP, deadlines and descriptor ownership
make zen-rust-glyph-rasterizer-qemu-test # Actual WebRender/FreeType glyphs on eight CPUs
make zen-rust-mtu-qemu-test # Actual MTU crate and native route snapshots
make zen-rust-socket2-qemu-test # Actual Socket2, message I/O and FD ownership
make zen-rlbox-runtime-qemu-test # Actual RLBox memory/minWASI, clocks and WABT traps
make zen-udp-core-qemu-test # Native UDP transport, packets and shared DNS/NTP leases
make zen-rust-quinn-udp-qemu-test # Actual Quinn, std UDP, packet metadata and cancellation
make zen-file-identity-qemu-test # Versioned metadata, ownership and independent remount
make zen-record-lock-qemu-test # Process ranges, close/dup2, contention and killed owners
make zen-sqlite-runtime-qemu-test # Actual configured DSO, extensions, WAL and remount
make zen-version-loader-qemu-test # Default/legacy ELF versions, requirements and TLS
make zen-sleep-qemu-test # Real timed/interruptible waits, SA_RESTART and UINT_MAX
make zen-shared-memory-qemu-test # Named RAM objects, processes, unlink lifetime and reboot
make zen-rust-neqo-udp-qemu-test # Actual Neqo wrapper over native Quinn UDP
make zen-rust-file-urls-qemu-test # Actual Gecko URL crate and native file readback
make zen-rust-os-consumers-qemu-test # Real Glean logging, errno and storage paths
make zen-rust-directories-qemu-test # Actual dirs crates and native XDG/account paths
make thread-platform-qemu-test        # TLS, lifecycle, pthread and sync fixtures
make virtual-memory-qemu-test         # VM, generated code, user-copy and faults
make vm-advice-qemu-test              # Discard/demand-zero and protection faults
make entropy-qemu-test                # RDRAND success and unavailable backend
./run-via-agent.sh                    # Bounded boot, 40 seconds by default
```

Native harnesses invoke `run-via-agent.sh` with bounded runs, disposable data
images and copied UEFI variables. They wait for USB initialization before login,
download the test ELF from a loopback server, and require its exact success
markers. Fault tests require the intended user fault and a responsive shell
afterward. Existing VM data and UEFI variables are preserved. A build or
host-model test alone does not establish guest behavior.

## Recorded verification through 2026-11-02

The following actual Alix guest results are retained under `build/test-out/`:

| Evidence log | Verified behavior |
| --- | --- |
| `cpp-runtime-qemu.log` | `CPP_RUNTIME_TEST: main PASS` and `fini PASS`: constructor priority, pre-main allocation, C/C++ ABI and reverse finalization. |
| `libcxx-runtime-qemu.log` | Eight concurrent binary file-stream roundtrips, append, 64-bit seek and missing-file checks; `main PASS workers=8 cpu_mask=0xFF counter=1024 tls_dtors=8`, followed by `exit PASS`. |
| `cxx-random-native-qemu.log` | Upstream random_device: 4,096 samples from eight pinned workers, diversity checks and operation with the descriptor table exhausted. |
| `cxx-random-unsupported-qemu.log` | CPU without RDRAND reports native ENOSYS through the real libc++ failure path; no substitute samples are returned. |
| `cxx-random-invalid-token-qemu.log` | The real upstream constructor rejects the unsupported token with ENOENT. |
| `posix-runtime-native-qemu.log` | Process-private semaphores: 20,000 tokens, 1,000 payload handoffs, timeout, signal interruption/posting; mutable `putenv` storage, independent spawn environment snapshots and `_exit` bypassing handlers. |
| `fd-stream-native-qemu.log` | Shared access/append/nonblocking status, independent CLOEXEC, atomic nonblocking pipe admission, `fdopen` lifetime/mode checks, append and 64-bit stream positions. |
| `socket-native-qemu.log` | Eight native IPv4 TCP connections: 128 KiB, flags, peek, safe copies and EOF; all eight queried endpoints matched to packets. Failed SO_ERROR copy preserves the refusal error, then exactly one of eight readers consumes it. |
| `netdb-native-qemu.log` | Eight callers pass controlled IPv4 DNS, multiple A/CNAME records, negatives and malformed responses, TLS/reentrant lookups, resolved TCP, safe-copy failure and killed-caller recovery. |
| `gecko-os-interfaces-qemu.log` | Eight pinned callers pass real file synchronization, alias/offset and unsupported-descriptor checks, checked WILLNEED advice and physical-page accounting. |
| `fsync-remount-qemu.log` | Independent boot reads all 64 KiB and metadata, plus an 8192-byte file shrunk/regrown with its zero-fill preserved, from the pre-shutdown private AlixFS snapshot. |
| `filesystem-primitives-qemu.log` | Eight CPUs pass file resizing/zero-fill, shared alias offsets and shared-node read snapshots, symlink-aware realpath, directory-only rmdir and invalid/read-only user-copy checks. |
| `fsync-legacy-root-qemu.log` | Disk written before the mount-root fix retains the new mount-point name and passes complete native file readback. |
| `select-native-qemu.log` | Eight pinned select waiters, all descriptor bits/highest slot, multi-set counts, monotonic timeouts, safe copies, TCP/EOF, exception-only hangup, close/reuse, EINTR and killed-caller cleanup. |
| `rust-libc-ffi-native-qemu.log` | Actual Gecko-vendored Rust libc linked to Alix: C/Rust scalar ABI, heap, environment, opaque FILE I/O, 64-bit offsets, pipes, sockets, address lookup, fsync, physical-page queries, select, ioctl, native system/credential identity and versioned stat/fchown. |
| `executable-path-native-qemu.log` | Kernel file loader and native spawn/PATH launch expose full absolute paths before main, independently of mutable argv/cwd; rename snapshot and invalid/short/read-only reply checks. |
| `rust-std-qemu.log` | Actual upstream std: native pthread identities/handles/TLS; File/OwnedFd ownership, offsets, resizing, paths, directories and pipes; 1,536 concurrent C/Rust environment updates, 512 snapshots, raw bytes, owned iterators, real cwd/executable paths and exact-uid account fallback; original allocation/time/synchronization/HashMap checks also pass. |
| `rust-file-urls-qemu.log` | Actual Gecko URL crate: native absolute paths, percent escaping, Unicode and invalid UTF-8 byte roundtrips, local/remote-host handling, NUL rejection at file open and eight-CPU file readback through decoded URLs. |
| `rust-os-consumers-qemu.log` | Actual Glean public FD logger delivers 256 JSON records from eight pinned CPUs; native errno crate/C errno isolation and strerror_r formatting, C/Rust errno/signal ABI, real storage-path module canonicalization/errors, and kill identity/error probes pass. XPCOM service startup and full browser linkage remain unverified. |
| `rust-directories-qemu.log` | Actual dirs/dirs-sys crates: eight CPUs parse real XDG files with HOME expansion, disabled/relative paths, escaping, Unicode and invalid UTF-8; defaults, overrides, account fallback and C/Rust passwd ABI; profile-directory creation and preferences write/sync/readback under the real default account config path. |
| `flock-native-qemu.log` | Eight pinned CPUs preserve 256 file updates under real shared/exclusive locks; advisory behavior, dup/final-close, rename, native inheritance, descriptor reuse, EINTR, storage progress and killed-waiter sibling-lock release pass. Rust File lock APIs independently pass 256 pinned critical sections in rust-std-qemu.log. |
| `ioctl-native-qemu.log`, `ioctl-legacy-qemu.log` | Eight CPUs pass 768 pipe snapshots, atomic nonblocking/shared-status behavior, per-slot CLOEXEC, file offset/EOF counts, exact copy widths and pointer errors; a separate legacy guest rejects controls without altering private flags. |
| `system-identity-qemu.log` | Running kernel build ID matches the booted ELF; credentials, checked copies and hostname bounds pass alongside 512 snapshots on eight CPUs during 64 atomic hostname replacements. |
| `nspr-file-abi-qemu.log` | Actual configured NSPR metadata/open and map/sync/unmap helpers pass native flags/sizes/offsets, timestamp conversion, shared visibility and error handling. Extracted functions use an instrumented error sink; complete NSPR startup is not tested. |
| `nspr-resources-qemu.log`, `nspr-resources-unsupported-qemu.log` | Whole upstream resource objects pass 512 eight-CPU samples, native memory/CPU counts, bounded short results, descriptor pressure and checked-copy errors. A separate CPU without RDRAND returns zero, maps ENOSYS and preserves output. Full NSPR initialization and production SSP startup are outside this fixture. |
| `synchronous-file-qemu.log`, `synchronous-file-remount-qemu.log`, `synchronous-file-legacy-qemu.log` | Eight pinned writers append 64 complete records; immutable sync state, shared offsets and checked inputs pass. A separate boot reads all 32 KiB and metadata without an explicit fsync; legacy wrapper and raw kernel reject sync without truncation. |
| `fd-limits-qemu.log`, `fd-limits-legacy-qemu.log` | 512 eight-CPU operations pass real FD quotas, atomic pipes, sockets, failed-truncate preservation, high slots, cross-page copies and spawn policy inheritance/isolation. A separate legacy guest rejects FD-limit calls without altering private limits. |
| `spawn-cwd-qemu.log` | Eight pinned launchers create 24 children with owned cwd actions, ordered relative opens, relative executable/PATH lookup, constructor-time cwd and parent isolation through failures. |
| `nspr-spawn-qemu.log` | Actual NSPR spawn helper launches 25 children, including crossed stdio and eight pinned callers; environment variants, CLOEXEC, blocking child streams, cwd/constructor state, failed-launch restoration and temporary-FD cleanup pass. Full NSPR initialization and wait daemon are not tested. |
| `dynamic-loader-qemu.log` | Real ELF code/dependencies, libc imports, constructor order, SysV/GNU hashes, packed relocations, 512 eight-CPU TLS updates, global/local binding retention, defined NULL symbols, error state, unload and NODELETE exit finalization. |
| `dynamic-loader-dtors-qemu.log`, `dynamic-loader-pinned-exit-qemu.log` | Eight C++ destructors retain code after dlclose and release it only after callbacks return; separate process exit finalizes with live threads and keeps code resident through termination. |
| `dynamic-loader-{relro,text}-qemu.log` | Hardware rejects writes to protected DSO data/code with the expected page faults and source locations; the shell recovers afterward. |
| `sigwait-qemu.log` | 512 directed waits across eight CPUs, eight competing process waiters, coalescing, checked-copy failures, handler retry/nesting and killed-waiter cleanup. Actual Rust libc mask/wait ABI also passes in `rust-libc-ffi-native-qemu.log`. |
| `file-mapping-qemu.log`, `file-mapping-remount-qemu.log`, `file-mapping-legacy-qemu.log` | Shared physical pages across threads/processes, 512 atomic updates, private isolation, VFS coherence, protection/unmap/close lifetimes and independent msync persistence. Legacy FDs remain isolated. |
| `nspr-runtime-qemu.log` | Full NSPR 4.40 library initialization, eight-thread synchronization/TLS, TCP gather/echo, pipes/events, shared maps, a child initializing NSPR, real wait-daemon status and cleanup. |
| `writev-qemu.log` | 512 atomic pipe records and 512 append records across eight CPUs, safe capture, overflow, bounded short writes, nonblocking admission and pipe SIGPIPE. |
| `ssp-loader-qemu.log`, `ssp-loader-corrupt-qemu.log` | Protected DSO constructor/calls use the main guard and native environment exports; an intentional overflow exits with verified status 127. |
| `rust-dynamic-loading-qemu.log` | Actual libloading/ash crates, native ELF code/imports, 512 thread-local updates, defined NULL symbols, error state and unload. Vulkan availability is not established. |
| `rust-std-net-qemu.log` | Native upstream std TCP: nine connections, 294,912 bytes, deadlines/refusal, FD ownership/cloning, CLOEXEC/nonblocking, peek/EOF, lookup and hostname. |
| `rust-glyph-rasterizer-qemu.log` | Actual WebRender FreeType backend: 512 glyph renders on eight CPUs, stable pixels/metrics, mono/alpha/subpixel modes, variable weights and raw/non-UTF-8 file-font equivalence. |
| `rust-mtu-qemu.log` | Actual MTU crate: 512 native route queries on eight CPUs, real outgoing interface/MTU, local/default routes, C ABI and checked-output errors. |
| `rust-socket2-qemu.log` | Actual Socket2 with all feature: nine TCP connections and 294,912 bytes, native deadlines, atomic flags, cloning, FD ownership, peek/EOF, gather/scatter, capture faults and NOSIGNAL after EOF. |
| `rlbox-runtime-qemu.log` | Actual RLBox memory/minWASI and default WABT runtime: eight aligned memories/traps, four clocks, native thread/process CPU samples, sleep exclusion and cleanup. |
| `rlbox-guard-qemu.log` | Exact native hardware write fault inside RLBox's reserved guard, compiled source verification and recovered shell. |
| `udp-owned-qemu.log` | Native owned UDP core on eight CPUs: 256 host exchanges, zero/max-MTU datagrams, peek/truncation, ownership, ECN/TOS/TTL and live DNS/NTP port coexistence, followed by userspace TCP download/TLS. |
| `quinn-udp-qemu.log` | Actual Quinn and std/public UDP sockets on eight CPUs: 256 host exchanges, wire-matched ECN/endpoints, source selection, empty/max-MTU packets, aliases/nonblocking, safe-copy failures and killed-caller port release. |
| `file-identity-qemu.log`, `file-identity-remount-qemu.log` | 512 snapshots on eight CPUs, old/new stat canaries, aliases/independent opens, readdir, rename/unlink/recreation, directory links, mount identities and independent readback of owner/group/mode 0640. |
| `record-lock-qemu.log` | Eight CPUs, 512 lock rounds, three children, PID/conflict queries, shared/exclusive splits, relative offsets, close-any-FD/dup2, killed holders/waiters, event progress and checked copying. |
| `sqlite-runtime-qemu.log`, `sqlite-remount-qemu.log` | Actual configured SQLite DSO: rollback/WAL, snapshots, separate-process busy/commit, eight writers, FTS5/vector extensions, integrity checks and 198 persisted rows. |
| `version-loader-qemu.log` | Versioned providers/consumers: default/legacy aliases, data, missing requirements, constructor order, eight-CPU dynamic TLS and unload. |
| `sleep-native-qemu.log` | Eight pinned CPUs: timed waits, sixteen caught-signal interruptions, SA_RESTART behavior, UINT_MAX durations, zero waits and errno. |
| `neqo-udp-qemu.log` | Actual Neqo/Quinn bridge: 128 host exchanges on eight CPUs, packet-verified endpoints/ECN/checksums, oversize PMTUD behavior and borrowed socket ownership. |
| `thread-elf_tls-qemu.log` | Eight CPUs passed initialized TLS, zeroed TLS, 128-byte alignment, constructors and thread-local errno checks. |
| `thread-libc-qemu.log` | Four-CPU allocator/once/TSD checks and exit ordering passed; required `main PASS` and `exit PASS` are present. |
| `thread-main_exit-qemu.log` | `MAIN_THREAD_EXIT_TEST: PASS main_joined=1 tls=1 last=1`: workers survive initial-thread exit and the last participant performs final cleanup. |
| `thread-pthread-qemu.log`, `thread-pthread_initial-qemu.log` | Pthread main/exit and initial-exit harnesses passed: eight CPUs, 1,024 increments, 128 fast joins, 32 detached threads and full pointer return from the initial thread. |
| `thread-rwlock-qemu.log` | Eight CPUs passed 1,024 writes, recursive readers, FIFO writers and bounded reader cohorts. |
| `thread-tls-qemu.log`, `thread-sync-qemu.log`, `thread-memory-qemu.log` | Raw FS state across all eight CPUs, four-CPU condition handoff, and 32 heap growth/shrink/regrowth rounds passed. |
| `thread-pool-qemu.log` | 256 joins with 2 MiB TLS per thread passed, reusing addresses across 512 MiB cumulative TLS allocation. |
| `virtual-memory-qemu.log` | 512 MiB sparse reservation, four readers, 128 protection changes, fixed replacement, RW-to-RX code and RWX code passed. |
| `user-copy-qemu.log` | Protected/unmapped buffers and a two-CPU, 128-round protection/copy race passed. |
| `vm-fault-{write,none,exec}-qemu.log` | Intended write, no-access and NX user faults occurred; the shell subsequently printed `fault_recovered`. |
| `vm-advice-qemu.log`, `vm-advice-fault-{write,none,exec}-qemu.log` | Discard/demand-zero passed 64 rounds with four readers, syscall-copy zero fill and POSIX content preservation. All three post-discard protection modes produced their expected faults and recovered shell. |
| `entropy-qemu.log`, `entropy-unsupported-qemu.log` | Eight CPUs completed 512 samples; a separate CPU configuration without RDRAND returned the expected unsupported result. |
| `stack-protector{,-corrupt,-no-entropy,-unprotected}-qemu.log` | Guard initialization precedes preinit/constructors; a real compiler epilogue detects corruption; protected startup rejects missing entropy while an unprotected process runs. |
| `math-atan2-qemu.log` | `atan2f` and `atan2l` preserve signed zero, special values, extended precision and extended exponent range. |
| `math-nearbyint-qemu.log` | LLVM's rounding implementation passed 32,742 cases across four modes, binary32/64 and x87-80, signed zero, signaling NaNs and preserved exception flags without new INEXACT. |
| `math-support-qemu.log` | Separate native LLVM math archive passed 39,861 sqrt/absolute-value/scaling cases across four modes, extended precision, range errno and exception flags. |
| `posix-entrypoints-qemu.log` | Owned `strdup` copies, captured `vprintf`/`perror` output, native regular-file mode/size and non-destructive checked `MADV_NORMAL` passed. |
| `stdio-buffer-qemu.log`, `stdio-buffer-exit-qemu.log` | All three buffering modes, positions, wide I/O and 128 close/global-flush races passed; a separate queued marker appeared through normal exit flushing. |
| `signal-jump-qemu.log` | Eight CPUs passed 64 real-fault handler jumps, 512 repeated checkpoints, masks/pending delivery, ancestor unwind, FP retention and stale/foreign rejection. |
| `process-uptime-qemu.log` | Eight CPUs passed 1,024 samples with a shared process creation epoch and elapsed sleep time. The real clock resolution remains 10ms. |
| `vfs-owned-bridge-qemu.log` | Real symlink/cwd snapshots, 4095-byte target boundaries, killed blocked caller cleanup and a fresh request passed, followed by public readlink truncation/error tests. Ordinary kernel restoration was verified. |
| `calendar-locale-qemu.log` | Gregorian UTC conversion, C/POSIX locale, TLS buffers across eight CPUs, real wall time and versioned timezone configuration snapshots passed. |
| `alix-toolchain-qemu.log` | Actual native Clang C++ output passed vector, compiler TLS, PID and stdio execution checks. |
| `cxx-stream-qemu.log`, `cxx-wide-qemu.log` | Real upstream narrow/wide streams, C/POSIX facets, 256 concurrent numeric roundtrips, 133,120 wide-mask checks and extended-precision conversions passed. |
| `stdio-stream-qemu.log`, `printf-locale-qemu.log`, `wide-stdio-qemu.log` | Synchronized records, byte/wide orientation, pushback/positions, 80-bit formatting, four rounding modes, bounded strings and owned locale handles passed. |
| `wchar-qemu.log`, `wchar-float-qemu.log`, `inttypes-qemu.log` | Native 16-bit code-unit/conversion contracts, wide 80-bit parsing and integer formatting/conversion interfaces passed. |
| `user-layout-qemu.log` | A 32 MiB ELF ran with a sparse 12 GiB reservation across high PML4 entries; eight CPUs passed high-address stack/TLS, safe copies, protection changes and generated code. |
| `exception-context-qemu.log` | 128 real demand-zero page faults across eight CPUs preserved 15 GPRs, stack, flags, x87 and SSE state through normalized exception entry. This is not user signal delivery. |
| `kernel-preempt-qemu.log` | The production preemption assembly, with its GS resume slot mapped to fixture memory, preserved registers, flags and both stack alignments despite an overwritten resume slot. This is a modeled-slot assembly test, not a controlled kernel-timer injection test. |
| `signal-{dispatch,default-fpe,abort-handler,abort-ignored}-qemu.log` | 2,048 callbacks executed on their calling threads; persistent/nested handlers and all deliberate process-termination modes returned control to the shell. Numeric exit codes are covered separately by host contracts. |
| `signal-kernel-{normal,default,badframe}-qemu.log` | Native fault/asynchronous delivery passed 96 signals on eight CPUs, GPR/SSE/x87 preservation, nested/edited alternate stacks, masks, sleep interruption and forged-return rejection. Default and corrupted-return modes matched exact kernel termination records and recovered the shell. |
| `timezone-qemu.log` | Eight CPUs passed POSIX rules, DST folds/gaps, formatting and 63 independently generated reference cases through real TZif files written and loaded inside Alix. |
| `tzdata-package-qemu.log` | The full pinned 2026f package staged 606 files twice, verified their hashes and passed 2,392 calendar cases across 598 names. Existing configuration and custom files were preserved; the package remained inactive. |
| `io-service-boot-qemu.log` | Protected workers passed three killed callers, independent cleanup while both storage workers blocked, two late-result releases, retained joins and shutdown waiting for a live caller. The following eight-CPU TLS test passed and the normal kernel was restored. |
| `resource-usage-qemu.log` | Eight CPUs produced increasing sampled CPU time and 128 recoverable faults; invalid selectors/output and the current zero-major-fault policy passed. The fault-context regression passed afterward. |

The earlier Rust fixture contains one `println!`, whose marker appeared twice
through legacy global console tapping and replay. The new private stdio profile
bypasses that tap, and native C/C++ tests verify exactly-once output. The Rust
fixture has not yet been rerun with the new owned descriptor runtime.

The full Alix build and linked native fixtures passed after the current pthread,
VM-advice, entropy, process-ID and math additions. Earlier engine-isolation and
runtime-archive checks passed for the 20 packaged applications. Doom and Quake
retain explicit 32-bit booleans; compiled layout probes preserved their existing
game structure sizes/offsets. All 16 source-acquisition tests passed, and the
real Firefox archive was verified against the pinned checksum before extraction.

The current patch suite passed nine preservation/application tests. Host
contracts passed for the new PID and stack-protector production paths, including
ASan/UBSan runs. The genuine Rust getrandom backend passed controlled short-read,
EINTR and failure cases. The corrected `zen-ssp-test` passed real compiler
instrumentation, optional-archive linking and first-preinit ordering. Its older
failure in `pid-ssp-integration-build.log` is superseded by that successful
rerun; it is not native execution evidence.

The first post-discard no-access run lost its armed marker to interleaved
emergency output. After separating the queued diagnostic from the deliberate
fault, both no-access and execute-protection harnesses passed with exact fault
address, privilege, error-code and source checks. An unrelated boot exposed
public stack-watch arming racing a remote scheduler claim. Serialized arming
passed a model reproducing that race. Follow-up validation made watched-frame
checks side-effect-free under scheduler locks, and shared kernel permission
updates now invalidate local translations even under a user CR3 when the PTE
already has the requested bits. Malformed-frame and stale-permission models
passed. The subsequent calendar, four stack-protector modes, raw TLS and native
toolchain guests all passed without unexpected faults.
UTC calendar/locale and the new timezone snapshot syscall have passed their host
contracts and native eight-CPU fixture. The refcounted FD table now owns native
directory streams and has host concurrency/sanitizer checks. The upstream
runtime's file/socket descriptors now use that same private table; the original
syscall IDs retain legacy behavior for existing binaries.
Owned TCP pool references now pass native eight-CPU lifetime tests and a real
16 KiB HTTP transfer after releasing the original owner. The event-driven TCP
executor also passes native pending-read multiplexing, three killed callers,
untouched abandoned output, cleanup and shutdown, with five packet-checked
FIN/ACK exchanges. Public descriptor routing is now connected through syscall
71. A later private-FD failure reproduced the earlier TLS stall's stranded
RUNNING state. Analysis against the retained failing kernel identified a
wake-before-park scheduler race: an early wake consumed before a stale park
could let a runnable caller switch away without being requeued. The production
regression failed before the fix and passed afterward; forced native stale
parks, private-FD acceptance and the following eight-CPU TLS guest all passed.
Earlier debugger/packet evidence remains preserved.
The protected I/O executor passed native cancellation, cleanup and shutdown
acceptance. The first run exposed deferred thread reclamation depending on a
later context switch on the former CPU. Bounded idle maintenance fixed that
progress gap; the same guest test then passed within its original deadline.
The new native private-FD fixture covers VFS/socket routing, capacity and
failed-truncate integrity, shared offsets, stdio and isolated capture. Native
user-parent exec inheritance remains separate work.
The original timezone fixture contains pinned 2026e regression data. The full
2026f IANA package has now passed native staging and runtime acceptance.
Atomic activation, ICU's native configured-zone identification and its separate
timezone data update still need integration. Native CPU fault/asynchronous
signal delivery, masks, alternate stacks and validated signal return now pass
guest acceptance. The explicit upstream Wasm context bridge now maps Alix's
named PC/BP/SP fields and passed its compile/patch contracts; actual Wasm
execution awaits the engine. Signal-aware nonlocal unwind now has native
acceptance; general interrupted-I/O restart remains unsupported.
Update this list only from actual guest markers and completed harness results.

A later pre-test password timeout was traced to input drivers compiling without
the shared USB feature definition, then polling an absent PS/2 controller
indefinitely. Explicit feature includes, common keyboard initialization, atomic
backend flags and bounded polling passed host checks in USB/PS2 configurations.
Seven subsequent native pthread/C++/Rust/protection guests passed serial login
and recovered the shell; the original debugger evidence is retained under
`build/ports/zen/usb-ps2-login-failure.*`.

## Primary upstream references

- [Pinned Zen source](https://github.com/zen-browser/desktop/tree/f75390aa2b797ddc3524ff9ed52ceb32a839f9fa)
- [Pinned source/base configuration](https://github.com/zen-browser/desktop/blob/f75390aa2b797ddc3524ff9ed52ceb32a839f9fa/surfer.json)
- [Zen build guide](https://docs.zen-browser.app/contribute/desktop/building)
- [Mozilla SpiderMonkey build and test guide](https://firefox-source-docs.mozilla.org/js/build.html)
