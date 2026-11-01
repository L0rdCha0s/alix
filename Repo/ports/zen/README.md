# Native upstream engine build

The pinned Firefox 159 standalone SpiderMonkey shell now passes native runtime
smoke tests for **Alix**. The current phase is Gecko, followed by Zen. The source is not configured as Linux and
does not use host C/C++ archives. Successful configuration or small runtime
fixtures do not establish that SpiderMonkey or Zen runs.

```sh
make zen-fetch
make zen-fetch-engine
make zen-cxx-runtime
make zen-rust-runtime
make zen-host-tools
make zen-patch-engine
make zen-patch-test zen-toolchain-test
make zen-ssp-test
make zen-js-build
python3 tests/spidermonkey_qemu_test.py --extended
make zen-gecko-configure
make zen-gecko-build
make zen-posix-runtime-qemu-test zen-fd-stream-qemu-test
make zen-rust-libc-ffi-qemu-test zen-executable-path-qemu-test
make zen-netdb-qemu-test
make zen-gecko-os-interfaces-qemu-test
make zen-select-qemu-test
make zen-cxx-random-qemu-test
make zen-filesystem-primitives-qemu-test
```

The source-acquisition commands precede patching. Once the source contains Alix
patches, `zen-fetch-engine` deliberately rejects the tree as non-pristine. Use
`zen-patch-engine` to check/reapply this patch set; it never resets the source.
The source and object directory remain under `ports/zen/upstream/`, outside the
FAT-backed `build/` directory used by QEMU. Normal `make` does not fetch or build
the upstream engine.

## Tracked source changes

`patches/series.json` identifies the exact Firefox revision, patch digests, and
before/after hashes of every affected source file. The base bytes were checked
against the pinned source archive. `patch_engine.py` validates all affected
files before changing any, uses forward/reverse `git apply --check`, then checks
the final digests. Unknown edits in an affected file or a partial application
stop the operation without overwriting source. Changes in other source files
are preserved. This check certifies the tracked patch inputs, not the entire
modified engine tree.

- `0001-recognize-alix-target.patch` adds Alix to GNU triplet canonicalization
  and Mozilla's OS/kernel enums, parser and compiler-preprocessor checks.
- `0002-detect-current-apple-host-linker.patch` handles the installed Apple
  linker's real `-v` banner when it no longer emits `LD_PRINT_OPTIONS`. It only
  affects Darwin host linker discovery; Alix uses native ELF binutils.
- `0003-validate-custom-rust-target.patch` accepts an explicit target JSON,
  verifies its OS/CPU and the compiler's actual target cfg, and retains the
  upstream `std`/`println!` static-library compile probe. Alix archives must
  contain native x86-64 ELF objects. It does not add a fabricated built-in Rust
  target or accept a `no_std` substitute.
- `0004-native-alix-getrandom.patch` adds an Alix backend to the actual vendored
  Rust getrandom 0.3.3 crate and updates its vendor file checksums. It calls the
  native libc entropy API, completes partial reads, retries EINTR and propagates
  failures without using a substitute random source.
- `0005-alix-icu-stdio-data-loader.patch` selects ICU's existing stdio data
  loader for Alix, which currently has anonymous VM but lacks file-backed
  mappings. ICU still reads, validates, allocates and releases real file data;
  this does not select `MAP_NONE` or fabricate `MAP_SHARED` semantics. Gecko's
  remaining file-mapping requirements still need native implementation.
- `0006-native-alix-wasm-context.patch` maps Wasm's x86-64 PC/SP/BP accesses
  to Alix's native `ucontext_t` named fields. It follows native eight-CPU
  signal-frame acceptance for register/FP preservation, nested alternate
  stacks, edited stack pointers, masks and invalid-frame rejection; it does
  not impersonate Linux's `gregs` ABI or disable Wasm trapping.
- `0007-native-alix-process-uptime.patch` queries Alix's real process creation
  timestamp through syscall 68, while retaining the existing POSIX monotonic
  clocks. The native uptime fixture passes 1,024 samples across eight CPUs;
  this branch neither reads Linux `/proc` nor returns a placeholder uptime.

- `0008-native-alix-spawn.patch` uses native POSIX spawn, copied environment
  snapshots and ordered pipe descriptor actions for the shell and Wasm workers.
  It preserves actual child PIDs, errors and waits. Alix-only failure diagnostics
  identify silent shell startup failures without changing their decisions.
- `0009-validate-alix-static-elf.patch` validates the native static executable
  rather than requiring a dynamic table. It rejects dynamic loaders/tables,
  allocated relocations, invalid or overlapping segments, writable executable
  segments and an entry outside file-backed executable memory.
- `0010-native-alix-mfbt-entropy.patch` fills mfbt random requests through native
  `getentropy` in bounded chunks and propagates failure. It avoids assuming
  Unix `/dev/urandom` exists and does not fabricate a random seed.

- `0011-native-alix-widget-toolkit.patch` selects `cairo-alix` for the Alix
  browser target. This selects the intended platform; it does not supply or
  certify a completed window backend.

## Native compiler and link driver

`toolchain/alix-clang` and `alix-clang++` use Clang with
`--target=x86_64-unknown-alix` and `__ALIX__`. Host C/C++ include searches are
disabled. Alix C headers, Clang target resource headers and the built native
libc++ headers supply the target environment. The runtime's current static
profile uses local-exec TLS, the existing large code model and Alix's wchar ABI.

Clang's generic Alix target delegates linking to the explicitly selected
`x86_64-elf-gcc` driver, which invokes native GNU ELF ld. It receives Alix's
startup/common objects, `user/lib/link.ld`, native libc++/libc++abi/support
archives and target libgcc. Runtime inputs are checked for x86-64 ELF identity;
Alix's old HTML/CSS/JS objects are rejected. Host libraries and a Linux dynamic
loader are not substitutes. Shared-object linking is an explicit unfinished
platform capability; the initial shell uses upstream `--disable-shared-js`.
The driver also supplies the optional native stack-protector archive. Actual
instrumented objects pull it in; it seeds the compiler's global guard from real
entropy before every user preinit/constructor and terminates if entropy is
unavailable. Unprotected executables do not acquire this requirement. See
`docs/kernel/stack_protector.md` for initialization and failure semantics.

`zen-js-configure` obtains the current runtime object list from the Makefile and
sets `--enable-project=js`, `--target=x86_64-unknown-alix` and the native drivers.
It leaves JIT and threading requirements intact. Host tools use the actual host
compiler/SDK. `MACH_NO_UV=1` avoids an incompatible installed host uv binary;
Mozilla's normal vendored Python environment is used with optional network
package installation disabled. `ALIX_LLVM_PREFIX` can select another LLVM
installation; `MOZ_PYTHON` can select the host Python executable.
The standalone profile builds bundled zlib. Its pkg-config search is restricted
to the initially empty Alix metadata directory, so host zlib cannot satisfy a
target dependency. `zen-host-tools` pins cbindgen 0.29.4, meeting this Firefox
source's minimum version, with Cargo's locked dependencies and a local
installation prefix. It does not replace the machine's tools.
The selected immutable native Rust std snapshot contributes an unused cfg flag
to Cargo's input fingerprint, forcing target crates to rebuild after a sysroot
update. It does not change an engine feature or fabricate a configure result.
Verified Rust port source digests contribute a separate cfg fingerprint. Cargo
otherwise treats vendored registry sources as immutable and can reuse the old
empty libc artifact after native bindings have changed. The fingerprint update
forces real recompilation while preserving previous cache artifacts.
Native header, object, archive and driver contents also fingerprint Mozilla's
compiler-probe cache. When those inputs change, the old `configure.cache` is
archived under project-specific `upstream/alix-toolchain/configure-cache-{js,browser}/configure-cache-history/` and configure
runs fresh real probes. This prevents an earlier missing libc function from
remaining cached as unavailable after it has been implemented.

`zen-js-build` first configures, then invokes upstream `mach build --priority
normal -j 2`. On hosts where a sandbox denies even `os.nice(0)`, this build
requires a permitted host execution context: upstream mach always calls that
API. No engine source patch or target-probe override bypasses the host failure.
`make zen-js-build ZEN_JS_KEEP_GOING=1` passes upstream's supported
`--keep-going` option to collect independent compiler failures in one run.
The final nonzero result remains authoritative; it does not accept incomplete
objects or override target probes.

## Current authoritative build result

The pinned upstream standalone SpiderMonkey shell now compiles and links
successfully. Full `make -C ports/zen/upstream/obj-js-alix -j2` exits zero,
including Rust, bundled ICU/zlib and the final native ELF validation. The actual
`dist/bin/js` is a static x86-64 Alix executable with no unresolved symbols or
runtime interpreter. `build/ports/zen/engine-native-entropy-build.log` records a
completed full build. The math runtime includes `nearbyint`, `nearbyintf` and
`nearbyintl`; these are no longer missing build functions. LLVM libc++ provides
C++ headers and runtime facilities, while Alix's C/math library supplies the
underlying C functions. The complete current math runtime uses pinned vendored
musl and FreeBSD sources rather than the earlier small LLVM rounding adapter.

`python3 tests/spidermonkey_qemu_test.py` builds the real shell and prepares a
transfer artifact with debug data stripped. Every load/TLS segment and the
entry point are verified identical to the original; hashes are recorded in
`build/ports/zen/spidermonkey-native-image.json`. The guest test encodes its JS
marker so command echo cannot satisfy acceptance and requires normal status 0.
The eight-CPU shell now executes the basic script and exits with status 0.
Module-loader startup required selecting libc++'s 16-bit wchar conversion path.
File-loaded scripts additionally required extending native stdio pushback for
three-byte BOM lookahead. Native C++ conversion, stdio, buffered and wide-stream
fixtures pass; host stream tests also pass sanitizers and allocation failures.
Native serial evidence is `build/test-out/spidermonkey-basic-qemu.log`.

`--extended` now passes observed Ion JIT execution, 10,000 rooted objects across
eight GC cycles, a real Wasm execution/bounds trap and worker shared Atomics.
Both test processes exit with wait status 0. Wasm compilation required a native
`calloc(0, ...)` policy returning distinct freeable ownership: its zero-element
metadata arrays interpret NULL as failure. The native allocator/lifecycle test
and host ASan/UBSan stress pass this change. Temporary compiler diagnostics have
been removed and the clean engine rerun passes. The serial log is
`build/test-out/spidermonkey-runtime-qemu.log`, and
`build/ports/zen/spidermonkey-native.acceptance.json` records the tested image
hashes and smoke scope. This does not claim the complete upstream conformance
suite, `os.spawn` command execution or Wasm subprocess serialization.

## Full Gecko build

`make zen-gecko-configure` and `make zen-gecko-build` use `--project browser`,
`cairo-alix` and `obj-gecko-alix`. Mozconfigs, compiler-cache state and logs are
separate from standalone SpiderMonkey; native headers/libraries and target
identity remain the same. Browser configuration does not pass the JS-only
`--disable-shared-js` option. `ZEN_GECKO_KEEP_GOING=1` selects the upstream
keep-going build mode. `ZEN_GECKO_JOBS` controls parallel compilation (default
two). Normal `make` remains independent of upstream builds.

The native browser configure passes toolkit/audio selection, the WASI sandbox
compiler/header/link probes and NSPR target selection. It now completes with `MOZ_WIDGET_ALIX` and the tracked native widget backend.
The browser build now passes the earlier executable-path, `putenv` and LLVM
file-stream compilation errors. The native Rust libc branch recompiles with its
new Cargo fingerprint; C/Rust ABI and file operations have separate guest proof.
Complete POSIX socket integration and further native platform dispatch remain build gaps.
The initial headers and outbound IPv4 TCP socket calls now pass a separate
eight-CPU guest test (`make zen-socket-qemu-test`), including 128 KiB transfer,
atomic flags, peek, per-call nonblocking and safe-copy checks. Native endpoint
and supported option queries also pass, including packet-matched addresses and
single-consumer SO_ERROR transactions after failed copyout. The actual vendored
Rust libc passes native socket ABI checks. Additional options, local IPC and UDP
still need implementation.
IPv4 DNS/netdb now passes a separate eight-CPU guest test with a controlled UDP
resolver: multiple records, CNAME follow-up, negative/malformed replies,
thread-local/reentrant results, resolved TCP transfers and killed-caller
cleanup. The actual Rust libc address-lookup ABI and NSPR's public networking
header also pass targeted checks. Default external DNS, full NSPR/NSS and the
complete browser remain unverified; see
[`docs/kernel/resolver.md`](../../docs/kernel/resolver.md).
The seventh complete diagnostic pass clears the missing netdb/select headers
and reaches Rust style compilation. It still fails after 21:14 on remaining
native platform interfaces. Native `fsync`,
physical-page `sysconf` queries and checked `MADV_WILLNEED` now pass eight-CPU
execution. The fsync fixture remounts a private disk in a second boot and reads
all 64 KiB plus metadata; it also caught and fixed AlixFS leaking the former
mount-point name into the new mount. Gecko's actual MemUtils and ggml-cpu objects
now compile. Dynamic loading, remaining NSPR definitions, local IPC/shared memory
and remaining Rust platform branches still block the complete browser build.
Native select now passes eight-CPU descriptor/TCP, signal, safe-copy,
close/reuse and killed-caller tests, plus real vendored Rust ABI/call checks.
NSPR uses the native descriptor-set header and implemented reentrant host and
protocol queries; its actual prnetdb.c compiles. The native style pthread header
fix also allows the complete nsDeviceContext.cpp source to compile. These are
individual translation-unit checks, not a complete NSPR/Gecko library link.
LLVM's actual random_device is now enabled with the native getentropy backend.
It passes eight-CPU diversity, descriptor exhaustion and real failure-path
tests. The complete existing libc++/libc++abi guest regression remains green,
and the actual llama-sampler.cpp source compiles. Native Rust pthread ownership
and handle extensions now pass eight-CPU identity/name/stack, consuming join,
detach and TLS checks. Gecko's actual Rust root build emits a fresh native style
library after selecting that API. Other root crate/platform errors still stop
the full Rust edge; the browser remains unbuilt.
Native ftruncate, realpath and directory-only rmdir now pass eight-CPU and
Rust libc ABI tests. The resized-file zero-fill survives an independent AlixFS
remount. NSPR's actual uxshm.c compiles, but file/shared mappings and the full
Rust filesystem backend remain unfinished.
Bindgen now receives the same native ABI/header configuration as the compiler
through its target-specific environment override; the actual profiler build
script generates bindings successfully. Native `sched_yield`/`sched_getcpu`
pass the eight-CPU C++ fixture. Gecko/Zen
have not run; successful configuration does not prove the widget C++ code builds
or executes.

`make zen-wasi-sdk` installs the pinned, hash-checked WASI SDK 34 used by the
browser's library sandboxes; it does not replace the native Alix target compiler.
The installer verifies every installed tool/sysroot file before reuse.

`make zen-cubeb-test` builds real upstream cubeb/Speex with the Alix mixer.
`python3 tests/cubeb_qemu_test.py` exercises native hardware playback, rate/format
conversion, simultaneous streams, pause/resume, drain, restart and destruction
from a callback. It also checks a captured window for both mixed tones, their
relative volume and frequency controls. Build/boot/ELF hashes and scope are saved
in `build/test-out/cubeb-native-qemu.acceptance.json`. The companion
`make zen-cubeb-profiler-test` and
`python3 tests/cubeb_qemu_test.py --profiler-provider` verify optional static
profiler hooks against a strong test provider. These are targeted smoke tests,
not the complete cubeb conformance suite or full audio quality acceptance.

`make zen-poll-qemu-test` verifies native private-descriptor polling. The kernel
pins every original description in a heap-owned request. Pipes, TCP, regular
files and imported non-TTY streams supply bounded readiness snapshots. Poll
supports monotonic timeouts, caught-signal interruption and killed-waiter cleanup.
The targeted acceptance receipt is `build/test-out/poll-native-qemu.acceptance.json`.

For kernel regressions against the already-built SpiderMonkey shell, use
`python3 tests/spidermonkey_qemu_test.py --extended --existing-image`. It skips
compilation, revalidates the upstream/native ELF load and TLS images, then runs
the existing executable and records the actual tested boot-image hashes. The
default test still rebuilds SpiderMonkey before running.

Native `posix_spawn`/`posix_spawnp` now pass environment visibility before main,
ordered close/dup2/open actions, CLOEXEC ordering, self-dup, PATH lookup, signal
attributes/inheritance and real error behavior in eight-CPU Alix. The existing
child lifecycle fixture also passes user-parent inheritance, cwd/argv, pipe EOF
before wait, status-copy rollback, eight competing waiters and parent-death
cleanup. Environment snapshots and child stack encoding pass host sanitizers.
See [`child_processes.md`](../../docs/kernel/child_processes.md).
The upstream adaptation removes fork/exec from this static shell's link needs;
`fork` and in-place `exec` have not been implemented. Its `os.spawn` command path
still requires a native `sh` executable, which is not installed.

Native math, C/C++ streams, signal-aware jumps, process uptime/accounting,
protected readlink, directory streams, private descriptor inheritance, pipes,
terminal classification, pthreads/TLS and anonymous VM have separate fixture
acceptance. Existing base applications retain the legacy descriptor ABI. General
file-backed/shared VM, callback VFS nodes, shell redirection, dynamic loading,
POSIX network integration and Gecko's widget/compositor remain later gates.

Nine offline tests exercise patch application, repeatability, new-file reversal,
preservation of unrelated edits and rejection of unknown/partial/wrong-base
inputs, symlinks and nonregular paths. A Rust host harness executes the real
native entropy backend against partial-read, interrupted and failed syscall
models; it is distinct from execution in Alix.
Five cache tests verify actual native input changes rerun compiler probes while
preserving their previous cache, and a real Cargo host fixture verifies external
native linker inputs trigger relinking of the Rust smoke executable.
`zen-toolchain-test` compiles a real vector/TLS/stdio fixture and verifies native
ET_EXEC, PT_TLS, no dynamic interpreter and no unresolved symbols. Its output is
`build/user/alix_toolchain_test.elf`, with runtime marker
`ALIX_TOOLCHAIN_TEST: PASS`; compilation/link checks do not execute it.

The standalone shell builds and executes JavaScript, with JIT and GC checks passing.
Gecko and the Zen UI are later native build/runtime gates, including the VM,
filesystem, networking and graphics interfaces demanded by their real source.

## Native widget implementation

`0015-native-alix-widget-backend.patch` selects the actual Alix widget directory,
application shell, XPCOM services, screen metadata, portable Gecko control theme,
text-event dispatcher and CPU-surface presentation. Window records, render
buffers and callback snapshots are heap-owned. The event pump preserves each
input snapshot across nested callbacks. Render/resize locks and compositor
shutdown protect the native window and draw target from concurrent destruction.

The implementation still needs full compilation and browser runtime validation.
File dialogs, the OS clipboard bridge, wheel input and the graphics/font platform
remain integration work. Native OpenGL is reported unavailable because Alix has
no native GL context API; the adapter supplies a software draw target. Mozilla's
explicit headless mode retains its ordinary headless widget implementation.

`0017-native-alix-rust-libc.patch` adds Alix's scalar ABI and implemented native
C entry points to Gecko's vendored libc crate, including vendor checksums.
The direct FFI fixture passes in an eight-CPU guest, including native fsync and
physical-page queries; this is not the complete
Rust dependency or standard-library filesystem/network port. The same managed
branch provides native fd_set/timeval/select bindings and bit operations, which
pass the actual Rust-to-Alix call fixture.
`0018-native-alix-executable-path.patch` calls the native launch-path API instead
of relying on argv or another OS's procfs. `0019-native-alix-portable-platform-types.patch`
selects native pthread thread IDs, ANGLE's generic POSIX TLS implementation and
opaque EGL declaration types. ANGLE's real TLS source and platform header probes
compile as native x86-64 ELF. This does not provide an EGL context or WebGL.
`0020-native-alix-library-headers.patch` avoids Cairo's internal `struct stat`
collision and selects Alix's alloca/endian headers in both NSS KaRaMeL copies.
The actual Cairo mask compositor, HACL/libcrux header probes and Gecko color-space
header compile. The browser C++ flags use the default rounding environment for
constant expressions; native C math keeps its separately tested fenv semantics.
These compile checks do not establish full Cairo/NSS runtime acceptance.
`0021-native-alix-style-thread-handle.patch` directly includes Alix's pthread
definition for cbindgen's existing native style-worker handle alias. The real
nsDeviceContext.cpp source now compiles; complete style Rust bindings and
runtime behavior still require full-build acceptance.
`0022-native-alix-rust-style-thread-handles.patch` selects the real Alix std
thread extension and maps its native handle condition through cbindgen.
The generated C++ alias remains Alix's actual pthread_t. A fresh native style
library and its get_thread_handles symbol are retained under obj-gecko-alix;
the regenerated-header C++ consumer also compiles. This is compile evidence,
not a running style engine or full browser.

`0016-native-alix-angle-program-version.patch` supplies the missing native rule
for ANGLE shader serialization metadata. It hashes the same common source set
already shared by Android and Linux; it does not select a Linux window or driver
implementation. The real generated header is under `obj-gecko-alix`.

`tests/keyboard_event_contract_test.py` verifies raw navigation/repeat events and
legacy terminal ANSI translation. The native window test additionally injects
an actual USB arrow press/release after the debugger resumes and requires one
raw down/up pair with no escaped text. This is OS input evidence, separate from
Gecko's still-unverified text-event adapter.
