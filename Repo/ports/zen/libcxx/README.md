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
Each worker also performs a real binary file roundtrip, append and update,
64-bit positioning without a large file allocation, and missing-file failure.
Require `CPP_STDLIB_TEST: files PASS threads=8 binary=1 append=1 seek64=1 missing=1`.

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

The complete C11 numeric runtime now belongs to ordinary USER_COMMON links,
including all real/complex math, floating-point parsing and the full FP
environment. The prior LLVM numeric adapters remain in the support archive for
compatibility, but fresh native links resolve these functions from the common
runtime. `make zen-math-runtime` packages the same complete implementation for
the Clang/Rust drivers. See [the native math notes](../libm/README.md) for pinned
source provenance, extended precision and validation.

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
code units. The Alix configuration selects libc++'s existing short-wchar
conversion path in both modern and C++03 headers. Merely passing `-fshort-wchar`
does not select that implementation: without this configuration, codecvt reads
pairs of 16-bit elements as 32-bit characters and rejects ordinary ASCII paths.
The native wide fixture reproduces that failure before the patch and passes
afterward, covering ASCII paths, UTF-8/UCS-2 conversion, bounds, partial output,
invalid surrogates and UTF-16 surrogate pairs (`codecvt16=1`).
The locale adapter translates libc++ class-mask bits through native
predicates instead of treating them as opaque `wctype_t` descriptors.
`zen-cxx-wide-test` builds `build/user/cxx_wide_test.elf` to test all class-mask
combinations, WEOF/non-ASCII cases, wide strings/streams and 80-bit roundtrips.
The native wide, inttypes and wide-float fixtures now pass; see
`build/test-out/cxx-wide-qemu.log`, `inttypes-qemu.log` and
`wchar-float-qemu.log` in the same directory. The existing output-routing issue
duplicates each small wcout write in serial output; the fixture does not issue
those writes twice.

Threads, RTTI, localization, wide-character facilities and file streams are enabled.
Patch `0006-native-alix-file-streams.patch` selects LLVM's existing file-stream
implementation independently of optional filesystem operations, and gates the
`filesystem::path` overloads with their real feature flag. C string and
`std::string` paths use native `fopen`/`fdopen`, `fseeko` and `ftello`.
Exceptions, filesystem, Unicode formatting facilities and terminal integration
remain disabled in this profile; implement and enable required facilities as the real Gecko build
demands them. The native C runtime now supports removal, rename, exclusive
creation, temporary files and all C11 floating-point environment operations;
see [the libc notes](../../../docs/kernel/libc.md).

Patch `0007-native-alix-random-device.patch` selects upstream libc++'s existing
getentropy implementation in both frontend configuration headers, and
`LIBCXX_ENABLE_RANDOM_DEVICE` is enabled. No random generator implementation is
replaced. Its default /dev/urandom constructor token selects the entropy API;
it does not open that path. `entropy()` retains LLVM's unknown-estimate result
for this backend. The existing no-exceptions profile aborts on unavailable
entropy or an invalid token rather than returning substitute samples.

Run `make zen-cxx-runtime`, then `make zen-cxx-random-qemu-test`. The actual
native executable passes 4,096 samples across eight pinned CPUs, a diversity
check and descriptor-table exhaustion. Separate guests verify native ENOSYS
without RDRAND and ENOENT for an unsupported token. The QA-only SIGABRT handler
exits after the real upstream diagnostics; neither failure returns random data.
`build/test-out/cxx-random-native-qemu.acceptance.json` matches all three boot
receipts to the exact target ELF. The general native libc++/libc++abi regression
also passes threads, TLS destructors, binary files, append, 64-bit seeks and
finalization after this feature is enabled. Gecko's actual llama-sampler.cpp
now compiles; this is not a complete Gecko or Zen build.


The toolchain defaults to Homebrew LLVM at `/opt/homebrew/opt/llvm`. It uses
Clang's target resource headers plus Alix headers, with host include searches
disabled, and GNU `x86_64-elf-ld`/libgcc for the final acceptance link. Normal
`make` never downloads or builds these optional upstream sources.
