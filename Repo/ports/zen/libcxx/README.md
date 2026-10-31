# Alix C++ runtime for the Zen port

This builds upstream LLVM 22.1.8 libc++ and libc++abi as **x86-64 ELF static
archives**, using Alix's own C headers and runtime. No host macOS/Linux C++
archive is linked. It is a prerequisite for the browser port, not a Zen build.

```sh
make zen-fetch-cxx
make zen-cxx-runtime
make zen-cxx-runtime-qemu-test
make zen-cxx-stream-test
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
external-threading adapter, and links against Alix libc. The general integer,
allocation, clock, classification and exit APIs live in `user/lib/libc.c`.

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

Threads and RTTI are enabled. Exceptions, filesystem, Unicode/wide-character
facilities, random-device and terminal integration remain disabled in this
profile; implement and enable required facilities as the real Gecko build
demands them. Existing `remove`/`unlink` remains unsupported by the native filesystem
syscall surface; this runtime does not turn that into a successful operation.
The C floating-point environment currently exposes rounding-mode access only.

The toolchain defaults to Homebrew LLVM at `/opt/homebrew/opt/llvm`. It uses
Clang's target resource headers plus Alix headers, with host include searches
disabled, and GNU `x86_64-elf-ld`/libgcc for the final acceptance link. Normal
`make` never downloads or builds these optional upstream sources.
