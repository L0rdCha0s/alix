# Native C11 library

Alix's user runtime implements the 496 runtime functions enumerated by
`tests/fixtures/libc_c11_functions.json`, derived from ISO C11 N1570 Annex B.
This includes 171 real math functions, 66 complex functions, 25 C11 threading
functions, all narrow/wide scanning families, and all floating-point environment
operations. Compiler-provided headers supply alignment, atomics, generic math,
integer types, variable arguments and the other language-support macros.
Optional Annex K bounds-checking interfaces and the wider POSIX/GNU surface are
outside this inventory.

`user/lib/libc.c` retains the native allocator, byte streams, formatting, process
lifecycle and blocking primitives. Additional modules provide calendar/timezone,
locales, wide characters, strings, file management, generic atomic operations,
C11 threads and scanning. `user/lib/libc_runtime.mk` supplies the complete runtime
to ordinary applications and the upstream ports. The kernel remains a separate
freestanding libc subset in `src/kernel/libc.c` and allocator in `heap.c`.

Native user `calloc` allocates a minimal distinct, freeable block when either
factor is zero, including `(0, SIZE_MAX)` and `(SIZE_MAX, 0)`. This is a
C11-permitted allocation policy and supports upstream empty arrays whose callers
treat NULL as allocation failure. Nonzero multiplication overflow still fails
with ENOMEM. The native allocator/lifecycle fixture and host ASan/UBSan stress
cover the empty allocations alongside coalescing, overflow and ownership.

## Numeric implementation

The runtime vendors musl 1.2.5 portable real and complex math. FreeBSD msun code
and ld80 adaptations replace incomplete long-double complex routines. Source
hashes and original licenses accompany the sources. Native long double retains
64 significand bits and the full x87 exponent range; extended functions do not
round through double. The native `frexpl` ABI helper remains in `user/lib/math.c`.
The compiler's complex multiply/divide helpers are extracted from its native
libgcc archive into a regular ELF object, preserving the runtime-object manifest
contract. See [the numeric port notes](../../ports/zen/libm/README.md).

The numeric library advertises `math_errhandling == MATH_ERREXCEPT`; native
`sqrtf` and `scalbnf` also preserve their existing errno contracts. Environment
operations cover x87 and SSE state together, including exception flags, masks,
rounding, save/restore and hold/update. Default native application flags preserve
dynamic rounding and disable floating-point contraction. The scheduler's FXSAVE
state keeps each thread's environment independent. C11 thread startup copies
the creator's current environment, including rounding and exception flags,
before invoking the new callback.

The compiler emits inline atomics for naturally aligned native 1/2/4/8-byte
objects. Larger aggregate atomics and 16-byte operations use a process-local
blocking gate. They report non-lock-free status and implement sequential
ordering, which is stronger than weaker requested memory orders. Shared state
and thread-start records live in process static/heap storage, never on another
thread's stack.

## Input, files and termination

All narrow and wide scanf/vscanf families use a private scanning stream over
Alix's public FILE implementation. Widths, suppression, scansets, length modifiers,
`%n`, hexadecimal/decimal floating input, infinity and NaN are supported. Public
stream scanning holds the stream mutex for the complete operation. Numeric
workspaces are heap owned; memory conversion supports arbitrarily long NaN
payload lookbehind without a bounded-buffer rewind. The same parser supplies
`strtof`, `strtod`, `strtold`, `atof` and the wide floating conversions in the
ordinary C runtime.

Installed C/POSIX locales use stateless ASCII. The uchar conversion functions
honor that installed encoding and reject unrepresentable values with EILSEQ;
they do not advertise an additional UTF-8 locale.

Exclusive `fopen` modes use an atomic VFS create check under the tree lock.
Append descriptors select EOF and commit each write under one node data lock,
including separate streams opened concurrently on different CPUs.
Removal and rename run on protected storage workers with copied, heap-owned
paths. Rename preserves node identity and ownership, rejects directory cycles
and cross-mount moves, and replaces a compatible destination atomically under
the tree lock. Nonempty directories and mount points are protected. Open streams
retain nodes across rename/removal; legacy opens now pin the reference before
releasing the tree lock too.

`tmpfile` creates exclusively and immediately removes its name, leaving the open
reference to own its lifetime. `tmpnam` returns process/sequence-based candidate
names; as required for a name-only API, callers must use exclusive creation to
avoid a name-to-open race. `freopen` preserves the FILE object's identity,
releases its old descriptor and resets orientation, positions and indicators.
A null filename is rejected with EINVAL; this implementation permits reopening
through an explicit filename only.

`at_quick_exit` uses a separate heap-owned LIFO callback list. `quick_exit`
executes that list and terminates through `_Exit`, without normal exit handlers
or stdio flushing. `system` runs the native Alix shell service synchronously,
collecting output through heap storage and returning its exit status in the
native wait-status encoding.

## Verification

```sh
make
make libc-complete-test
python3 tests/libc_c11_api_test.py
python3 tests/libc_complete_qemu_test.py
```

The API check requires all 496 definitions in the actual runtime objects and
compiles references through every relevant public header. The native fixture
checks 708 independent high-precision numeric vectors, additional ld80 range
and precision cases, scanning, temporary files, exclusive create, reopen,
rename/unlink with an open descriptor, C11 threads/TLS/once, condition variables,
mutexes, FP-state isolation and 16-/24-byte aggregate atomics across eight pinned
CPUs. The QEMU runner uses `run-via-agent.sh`, disposable disks and the existing
isolated native-ELF harness. Evidence is retained in
`build/test-out/libc-complete-qemu.log`.

This is complete coverage of the audited function surface with representative
runtime and regression evidence. It is not a formal conformance certification
or exhaustive numerical/behavioral verification of every standard-library
edge case. The test inventory and runtime markers make that distinction explicit.
