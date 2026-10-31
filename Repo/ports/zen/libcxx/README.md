# Alix C++ runtime for the Zen port

This builds upstream LLVM 22.1.8 libc++ and libc++abi as **x86-64 ELF static
archives**, using Alix's own C headers and runtime. No host macOS/Linux C++
archive is linked. It is a prerequisite for the browser port, not a Zen build.

```sh
make zen-fetch-cxx
make zen-cxx-runtime
make zen-cxx-runtime-qemu-test
make zen-cxx-stream-test
make zen-cxx-wide-test zen-wchar-float-test
make libc-support-host-test
```

The LLVM base revision is pinned in `upstream.json`. Source, CMake output and
archives stay under `ports/zen/upstream/`, outside QEMU's FAT-backed `build/`
directory. Fetch preserves existing port edits. Build applies the tracked
patches in `patches/` without replacing unrelated source modifications.

The native acceptance executable is `build/user/libcxx_runtime_test.elf`.
It must execute inside Alix, with both `CPP_STDLIB_TEST: main PASS` and
`CPP_STDLIB_TEST: exit PASS`, before claiming the runtime execution gate passed.
The test uses eight CPU-bound standard C++ threads, mutexes/condition variables,
thread-local initialization and destructors, global exit order, vectors,
strings, over-aligned allocation, integer/floating conversion and clocks.

The native C fixture `tests/thread_libc_support_test.c` additionally checks
aligned allocation/reallocation/coalescing and overflow preservation, integer
boundaries, odd-width sorting, four-CPU recursive/once/TSD behavior, destructor
repopulation, deleted-key generations, filtered/reentrant C++ finalization and
concurrent process exit. Require both `LIBC_SUPPORT_TEST: main PASS` and
`LIBC_SUPPORT_TEST: exit PASS`. `libc-support-host-test` executes the same
production allocator/parser functions under ASan/UBSan with 25,000 heap
mutations and 50,000 parser comparisons; host checks do not substitute for
guest execution.

The external-threading implementation maps libc++'s documented interface to
Alix's mutex, condition, once, TLS-key, thread-create/join/detach and sleep APIs.
Thread startup arguments are heap-owned. It does not emulate OS calls by
returning successful stubs. The native C++ ABI calls the real libc
`__cxa_thread_atexit_impl` implementation. The acceptance executable uses
hosted C++ entry semantics and explicitly enables C++ destructor registration.

Alix libc implements process exit callbacks, C++ finalization, per-thread
destructor stacks and generation-checked TSD keys. TLS values use the actual
ELF TLS block. Keys support four destructor iterations, matching the usual
POSIX/C11 destructor-repopulation contract. DSO lifetime handling currently
assumes static ET_EXEC images; shared-library unloading still needs integration.

The numeric support object `user/lib/strtofloat.cpp` uses the pinned LLVM libc
freestanding parser for `strtof`, `strtod` and `strtold`, independently of the
browser engine and libc++. It is part of `libalix-cxx-support.a`, alongside the
external-threading adapter and C-compiled `wcstofloat.c` wrappers, and links
against Alix libc. Wide floating conversion is kept out of USER_COMMON so C
programs do not acquire an unresolved optional parser dependency. The general integer,
allocation, clock, classification and exit APIs live in `user/lib/libc.c`.

The separate [native libm archive](../libm/README.md) now supplies the math
exports, instead of putting them in the C++ support archive. Its
`user/lib/llvm_nearbyint.cpp` supplies native `nearbyint`, `nearbyintf` and
`nearbyintl` from the same pinned LLVM libc support subtree. It reuses the
upstream format-aware rounding algorithm and obtains the mode from native
`fegetround`; the generic upstream arithmetic mode probe would itself set
FE_INEXACT. Signaling NaNs take a real hardware invalid operation. LLVM's
private full-build support types stay inside this object: no private fenv
structure or exception encoding crosses the Alix ABI. Only `fegetround` is an
external dependency. `tests/nearbyint_contract_test.py` compares 99,625 cases
with host libm under all four modes (also ASan/UBSan); `make zen-nearbyint-test`
links the separate native x87/SSE and 80-bit acceptance fixture. This fixture
now passes inside Alix with 32,742 cases, four rounding modes, extended-precision
values, signaling NaNs and preserved exception flags.

The numeric exports are currently optional for ordinary Alix C applications:
declaring them through `math.h`/`stdlib.h` does not add the archive to the normal
USER_COMMON link. The native `ports/zen/toolchain/alix-clang` driver adds
the math archive and `libalix-cxx-support.a` automatically, including for C sources. A normal
Makefile C target can instead append
`ports/zen/upstream/libm-alix-build/lib/libalix-math.a` for math or
`ports/zen/upstream/libcxx-alix-build/lib/libalix-cxx-support.a` for numeric
parsing after its own objects, within the existing libgcc link group. The
nearbyint object pulls only native `fegetround`; it does not require libc++.
`zen-nearbyint-test` shows the driver-based C link.

Further libm work should reuse this LLVM libc subtree where supported. Its
rounding, exponent/scaling, remainder, nextafter and square-root helpers are
freestanding, including x87-80 support. Float/double transcendental functions
add upstream range-reduction tables and multiword arithmetic, plus a deliberate
native errno/fenv adapter; they do not need a Linux kernel ABI. The pinned
generic tree does not provide `sinl`, `cosl`, `expl`, `logl` or `powl`, and its
`atan2l.cpp` explicitly rejects extended precision. Source availability alone
is therefore insufficient to claim a complete 80-bit libm replacement.

The runtime now builds localization and iostream code through a native Alix
locale adapter. It uses owned C/POSIX locale handles and upstream's C character
table; unsupported named locales are rejected instead of pretending translated
facets exist. ICU provides its own internationalization data. The adapter keeps
thread locale selection scoped around formatting calls and uses Alix stdio.

The separate `build/user/cxx_stream_test.elf` acceptance fixture exercises C
classification/collation, integer and floating output, numeric input, 80-bit
precision/exponents, real cout output and eight concurrent stream users. Require
`CXX_STREAM_TEST: PASS workers=8 roundtrips=256 extended80=1` in Alix before
claiming stream execution; the previous vector/thread fixture does not establish
this new gate. This stream marker and the separate stdio/80-bit formatter
fixtures now pass in the eight-CPU Alix guest; see
`build/test-out/cxx-stream-qemu.log`, `stdio-stream-qemu.log` and
`printf-locale-qemu.log` in the same directory. The fixture writes its cout line
once, but current kernel console-tap/capture routing duplicates it in serial
output. That separate descriptor/output-routing issue remains under repair.

The wide profile now compiles with the native 16-bit wchar ABI. Its C/POSIX
multibyte conversion accepts the installed ASCII encoding; it does not pretend
that a UTF-8 locale is installed. Wide strings can independently store UTF-16
code units. The locale adapter translates libc++ class-mask bits through native
predicates instead of treating them as opaque `wctype_t` descriptors.
`zen-cxx-wide-test` builds `build/user/cxx_wide_test.elf` to test all class-mask
combinations, WEOF/non-ASCII cases, wide strings/streams and 80-bit roundtrips.
The native wide, inttypes and wide-float fixtures now pass; see
`build/test-out/cxx-wide-qemu.log`, `inttypes-qemu.log` and
`wchar-float-qemu.log` in the same directory. The existing output-routing issue
duplicates each small wcout write in serial output; the fixture does not issue
those writes twice.

Threads, RTTI, localization and wide-character facilities are enabled.
Exceptions, filesystem, Unicode formatting facilities, random-device and terminal integration remain disabled in this
profile; implement and enable required facilities as the real Gecko build
demands them. Existing `remove`/`unlink` remains unsupported by the native filesystem
syscall surface; this runtime does not turn that into a successful operation.
The C floating-point environment currently exposes rounding-mode access only.

The toolchain defaults to Homebrew LLVM at `/opt/homebrew/opt/llvm`. It uses
Clang's target resource headers plus Alix headers, with host include searches
disabled, and GNU `x86_64-elf-ld`/libgcc for the final acceptance link. Normal
`make` never downloads or builds these optional upstream sources.
