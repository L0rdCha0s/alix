# Native Zen Browser port

## Direction and current status

The new browser uses **Zen's Firefox/Gecko/SpiderMonkey stack** for HTML, CSS,
layout, JavaScript and browser chrome. Alix supplies the operating-system and
window-system interfaces. The existing `user/lib/web` and `atk_html_view` engine
is not part of the new port.

**Zen does not build or run on Alix yet.** The pinned standalone SpiderMonkey
configuration now succeeds for `x86_64-unknown-alix`, and the real upstream build
has started compiling target dependencies. The shell has not yet linked or run.
Native Alix guests have executed upstream LLVM libc++/libc++abi and upstream
Rust `std` using Alix's runtime. ELF TLS, thread lifecycle, anonymous virtual
memory, permission-checked user copies and hardware-backed entropy have native
acceptance evidence. These are platform prerequisites, not browser completion.
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
  This profile enables RTTI and threads but disables exceptions, filesystem,
  localization, Unicode/wide-character, random-device and terminal facilities.
  Shared-library unloading is not implemented. See
  [`ports/zen/libcxx/README.md`](../ports/zen/libcxx/README.md).
- **Upstream Rust runtime.** Rust 1.97.1 `core`, `alloc` and `std` are rebuilt
  for the explicit custom Alix target with a native platform layer. Allocation,
  console IO, arguments, time, futex-based synchronization, threads, TLS cleanup
  and entropy-backed `HashMap` have guest evidence. The target uses static
  relocation, local-exec TLS and `panic=abort`; it does not pretend to be Linux
  or a built-in Rust target. Filesystem, network and process-creation backends
  still return unsupported errors. Environment, unwinding, dynamic loading and
  ecosystem platform dispatch need further work. See
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
  tests passed; the remaining fault-mode QA is recorded below. Shared and
  file-backed mappings remain unsupported. The present 4–8 GiB user window
  provides about 2.7 GiB of VM arena, so larger browser reservations still need
  address-layout expansion. See [`kernel/memory.md`](kernel/memory.md).
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

The tracked native toolchain uses Clang 22.1.8, Alix C headers, native libc++
and GNU ELF linking with Alix's CRT/linker script. It rejects host libraries,
dynamic interpreters and legacy Alix web-engine objects. The Rust configure
patch validates the declared target JSON and actual compiler cfg, then retains
Mozilla's genuine `std`/`println!` static-library probe and ELF-object checks.
The native SpiderMonkey profile uses bundled zlib and leaves JIT/threading
requirements enabled. Target-specific Rust dependencies still need their own
Alix backends even though the standard-library probe succeeds.

The recorded `build/ports/zen/spidermonkey-configure.log` reaches
`Configure complete!`. The latest completed build in
`build/ports/zen/spidermonkey-build.log` passes the previous vendored getrandom
and `atan2f`/`atan2l` gates: the native getrandom 0.3.3 backend and compatibility
shim compile, and ICU progresses beyond libc++ complex. The real upstream
Rust `libjsrust.a` now builds with LTO: its 52,486,052-byte archive contains ten
native ELF64 x86-64 members. Rebuilding Alix's Rust standard library with embedded
bitcode resolved the earlier `.llvmbc` error. Native `gettimeofday`, UTC calendar
conversion, C/POSIX locale, timezone conversion/formatting, `strncat`, and C
signal APIs are implemented. Native timezone and signal fixtures passed.
The next actual build has compiled ICU's existing stdio data loader on Alix,
preserving data-file access while file-backed VM remains unavailable. It has
advanced beyond the previous missing time/signal headers and file-map compile
errors. The latest completed build now reaches Mozilla's `Maybe.h` stream
insertion code, where the bootstrap libc++ profile lacks locale/iostream support.
That native C++ runtime profile must be expanded; a complete SpiderMonkey
executable is still pending. The earlier
`build/ports/zen/gecko-configure.log` triplet rejection is historical, not the
current blocker. See [`ports/zen/README.md`](../ports/zen/README.md) for detailed
patch/compiler contracts and the latest build diagnostics.

The remaining acceptance order is:

1. Complete the actual standalone SpiderMonkey compile/link, then execute its
   shell and upstream JS tests inside Alix, including GC/JIT and worker paths.
   Standalone `JS_WITHOUT_NSPR` avoids requiring NSPR first. Passing the existing
   Alix JS interpreter or a runtime fixture does not satisfy this engine gate.
2. Complete the OS interfaces demanded by Gecko, NSPR/NSS and Rust dependencies.
   User file descriptors currently share a global 32-slot table. Per-process
   ownership, reference-counted open descriptions, dup/shared offsets, correct
   stdio inheritance and cancellation-safe blocking-IO cleanup are required.
   Then connect real Rust filesystem/descriptor backends. General userspace
   process creation, IPC, shared memory, poll/select, dynamic loading, and the
   required POSIX filesystem/network surface remain unfinished. Existing socket
   syscalls are custom TCP/IPv4 interfaces; native DNS/TLS code alone does not
   establish Gecko/NSS integration.
3. Implement Gecko widget/event-loop/software composition in Alix windows.
   Extend input for scrolling, focus, text composition and clipboard as needed;
   current events cover mouse/key/resize/close. Prove upstream HTML/CSS layout,
   script execution, input and resizing in the guest.
4. Apply the pinned Zen overlay to the working Gecko platform and verify
   navigation, HTTPS, tabs, profiles, downloads, fonts and browser lifecycle in
   QEMU. Package a real native ELF and switch the default browser only after
   these tests pass.

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
make zen-rust-runtime-qemu-test        # Actual upstream Rust std in Alix
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

## Recorded verification on 2026-10-31

The following actual Alix guest results are retained under `build/test-out/`:

| Evidence log | Verified behavior |
| --- | --- |
| `cpp-runtime-qemu.log` | `CPP_RUNTIME_TEST: main PASS` and `fini PASS`: constructor priority, pre-main allocation, C/C++ ABI and reverse finalization. |
| `libcxx-runtime-qemu.log` | `CPP_STDLIB_TEST: main PASS workers=8 cpu_mask=0xFF counter=1024 tls_dtors=8`, followed by `exit PASS`. |
| `rust-std-qemu.log` | `RUST_STD_TEST: PASS workers=8 cpu_mask=0xFF count=1024 tls_dtors=8 hashmap=256`: real upstream std, allocation/formatting, time, synchronization and entropy-backed hashing. |
| `thread-elf_tls-qemu.log` | Eight CPUs passed initialized TLS, zeroed TLS, 128-byte alignment, constructors and thread-local errno checks. |
| `thread-libc-qemu.log` | Four-CPU allocator/once/TSD checks and exit ordering passed; required `main PASS` and `exit PASS` are present. |
| `thread-main_exit-qemu.log` | `MAIN_THREAD_EXIT_TEST: PASS main_joined=1 tls=1 last=1`: workers survive initial-thread exit and the last participant performs final cleanup. |
| `thread-pthread-qemu.log`, `thread-pthread_initial-qemu.log` | Pthread main/exit and initial-exit harnesses passed: eight CPUs, 1,024 increments, 128 fast joins, 32 detached threads and full pointer return from the initial thread. |
| `thread-tls-qemu.log`, `thread-sync-qemu.log`, `thread-memory-qemu.log` | Raw FS state across all eight CPUs, four-CPU condition handoff, and 32 heap growth/shrink/regrowth rounds passed. |
| `thread-pool-qemu.log` | 256 joins with 2 MiB TLS per thread passed, reusing addresses across 512 MiB cumulative TLS allocation. |
| `virtual-memory-qemu.log` | 512 MiB sparse reservation, four readers, 128 protection changes, fixed replacement, RW-to-RX code and RWX code passed. |
| `user-copy-qemu.log` | Protected/unmapped buffers and a two-CPU, 128-round protection/copy race passed. |
| `vm-fault-{write,none,exec}-qemu.log` | Intended write, no-access and NX user faults occurred; the shell subsequently printed `fault_recovered`. |
| `vm-advice-qemu.log`, `vm-advice-fault-{write,none,exec}-qemu.log` | Discard/demand-zero passed 64 rounds with four readers, syscall-copy zero fill and POSIX content preservation. All three post-discard protection modes produced their expected faults and recovered shell. |
| `entropy-qemu.log`, `entropy-unsupported-qemu.log` | Eight CPUs completed 512 samples; a separate CPU configuration without RDRAND returned the expected unsupported result. |
| `stack-protector{,-corrupt,-no-entropy,-unprotected}-qemu.log` | Guard initialization precedes preinit/constructors; a real compiler epilogue detects corruption; protected startup rejects missing entropy while an unprotected process runs. |
| `math-atan2-qemu.log` | `atan2f` and `atan2l` preserve signed zero, special values, extended precision and extended exponent range. |
| `calendar-locale-qemu.log` | Gregorian UTC conversion, C/POSIX locale, TLS buffers across eight CPUs, real wall time and versioned timezone configuration snapshots passed. |
| `alix-toolchain-qemu.log` | Actual native Clang C++ output passed vector, compiler TLS, PID and stdio execution checks. |
| `signal-{dispatch,default-fpe,abort-handler,abort-ignored}-qemu.log` | 2,048 callbacks executed on their calling threads; persistent/nested handlers and all deliberate process-termination modes returned control to the shell. Numeric exit codes are covered separately by host contracts. |
| `timezone-qemu.log` | Eight CPUs passed POSIX rules, DST folds/gaps, formatting and 63 independently generated reference cases through real TZif files written and loaded inside Alix. |

The Rust fixture contains one `println!`. Its marker appears twice because
current global console routing taps output into shell capture as well as
emitting it directly; later replay duplicates it. This is a pending per-process
stdio-routing fix, not two independent Rust acceptance runs.

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
contracts and native eight-CPU fixture. The standalone refcounted FD table
has host concurrency/sanitizer checks but is not wired into kernel I/O yet.
The timezone fixture contains pinned 2026e regression data. A full production
IANA data package and ICU's native configured-zone identification still need
integration. C `raise` is synchronous; CPU fault delivery, signal masks,
alternate stacks and validated signal return remain required for Wasm.
Update this list only from actual guest markers and completed harness results.

## Primary upstream references

- [Pinned Zen source](https://github.com/zen-browser/desktop/tree/f75390aa2b797ddc3524ff9ed52ceb32a839f9fa)
- [Pinned source/base configuration](https://github.com/zen-browser/desktop/blob/f75390aa2b797ddc3524ff9ed52ceb32a839f9fa/surfer.json)
- [Zen build guide](https://docs.zen-browser.app/contribute/desktop/building)
- [Mozilla SpiderMonkey build and test guide](https://firefox-source-docs.mozilla.org/js/build.html)
