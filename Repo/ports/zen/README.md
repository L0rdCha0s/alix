# Native upstream engine build

The current gate is the pinned Firefox 159 standalone SpiderMonkey shell for
**Alix**, followed by Gecko and Zen. The source is not configured as Linux and
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
Native header, object, archive and driver contents also fingerprint Mozilla's
compiler-probe cache. When those inputs change, the old `configure.cache` is
archived under `upstream/alix-toolchain/configure-cache-history/` and configure
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
The initial eight-CPU run loaded the executable and started native helper threads,
then exited with code 1 during module-loader path conversion. Native regression
tests identified a libc++ configuration mismatch: the compiler used 16-bit
`wchar_t` while codecvt selected its 32-bit implementation. The short-wchar patch
now passes ASCII/Unicode conversion and the existing C++ runtime tests in Alix;
the real engine is being rebuilt for execution verification. This is successful
build/link acceptance, not JavaScript execution or Zen acceptance. Native serial evidence is
`build/test-out/spidermonkey-basic-qemu.log`.

`--extended` additionally requires observed Ion JIT execution, rooted objects
surviving eight GC cycles, a real Wasm memory-bounds trap and a worker exchanging
data through shared Atomics. Those gates are separate from the basic script and
must pass in the guest before claiming runtime acceptance.

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

The standalone shell builds and starts but has not yet executed the test script.
Gecko and the Zen UI are later native build/runtime gates, including the VM,
filesystem, networking and graphics interfaces demanded by their real source.
