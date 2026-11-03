# Native C11 library

Alix's user runtime implements the 496 runtime functions enumerated by
`tests/fixtures/libc_c11_functions.json`, derived from ISO C11 N1570 Annex B.
This includes 171 real math functions, 66 complex functions, 25 C11 threading
functions, all narrow/wide scanning families, and all floating-point environment
operations. Compiler-provided headers supply alignment, atomics, generic math,
integer types, variable arguments and the other language-support macros.
Optional Annex K bounds-checking interfaces and the wider POSIX/GNU surface are
outside this inventory.

The additional native OS interface includes `uname`, `gethostname` and the
real/effective user and primary-group getters. Their ABI, kernel build ID,
hostname ownership and current single-identity semantics are documented in
[system identity](system_identity.md).

The upstream resource profile implements enforced per-process descriptor
limits, while the ordinary runtime rejects private FD-limit operations.
Both profiles query the current address-space quota through checked kernel
metadata copies. See [descriptor limits](descriptor_limits.md).

Native ELF shared libraries, symbol lookup and dynamic TLS now have real
eight-CPU execution evidence. See [dynamic loading](dynamic_loading.md) for
the executable export contract, lifetime rules and remaining ABI limits.

Native `sigwait` accepts blocked signals through the shared kernel registry,
including competing waiters and use inside a signal handler. Its error-number,
mask and checked-copy contracts are documented in [signals](signals.md).

The owned runtime also supplies regular-file shared/private mappings and
`msync`. The same ABI is available through Gecko's vendored Rust libc; see
[file mappings](file_mappings.md) for lifetime, persistence and current limits.

Native `writev` gathers checked inputs into one owned write request, preserving
the backend's pipe atomicity and append/offset serialization. See
[vectored I/O](vectored_io.md).

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

The POSIX `random`, `srandom`, `initstate` and `setstate` family uses pinned musl
1.2.5 code with Alix's existing mutex. Its 31-bit stream is separate from `rand`.
State buffers remain caller-owned and must stay live while active. Native
eight-CPU acceptance covers concurrent generation, reseeding, state restoration,
range and independent `rand` state; run `make zen-random-qemu-test`. These are
deterministic generators. `getrandom`/`getentropy` provide the kernel entropy API.

GNU-compatible `memalign` delegates to the existing native aligned allocator.
It accepts arbitrary allocation sizes and power-of-two alignments, preserves
errno on success and returns a freeable allocation for size zero. Invalid
alignments and unrepresentable sizes report EINVAL/ENOMEM. The native Gecko
font fixture exercises it directly and through Mozilla's real `moz_xmemalign`.

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

## POSIX environment and semaphore additions

`putenv` retains the caller's assignment storage. Both name and value are
resolved from its current bytes on each lookup; caller edits are observable.
Replacing or removing an entry frees only libc-owned backing, including the
self-alias case where an assignment points into an earlier owned value.
`setenv` still copies its input. Spawn captures an independent owned snapshot
under the environment mutex. The no-equals `putenv("NAME")` removal extension
is supported. The application owns borrowed storage lifetime and synchronizes
its direct edits. `_exit` uses immediate process termination without normal
exit callbacks or stdio flushing.

Native Rust environment access uses `alix_environment_copy`/free instead of
retaining the pointer returned by getenv after releasing the C lock. Values
and enumeration iterators therefore retain independent bytes across C/Rust
updates. Eight CPU-pinned workers pass 1,536 updates and 512 snapshots, including
shared-value replacement; non-UTF-8 variables and borrowed putenv storage are
also checked in `rust-std-qemu.log`.

`pwd.h` supplies getpwuid_r/getpwnam_r and the native 48-byte passwd structure;
uid_t/gid_t are 32-bit. Lookup reads Alix's `login:uid:gid:display:home` database
with a 64 KiB bound, skips malformed/overflowing numeric records and copies
matching fields into the caller's buffer. Relative homes resolve from `/`, as
login does. No match returns 0 with a NULL result; ERANGE and other errors do not
publish a record. The public database has no password-hash or shell field, so
those returned strings are empty. There is no invented root fallback or account
enumeration API. Native Rust HOME fallback now calls this exact-uid interface;
the older alix_home_dir helper retains its existing legacy contract.

Production account host contracts pass ASan/UBSan and TSan with 8,000 concurrent
uid/name lookups, allocation/I/O failures, EINTR retry, bounds, malformed ids and
caller-owned output storage. Native Rust guest checks validate actual account
records, ABI field access, missing-user behavior and HOME fallback.

`semaphore.h` supplies process-private unnamed semaphores through native
atomics and futex waiting. Post publishes payload data before token consumption;
the sequence/waiter protocol prevents a lost wakeup. Timed waits use absolute
realtime deadlines and bounded relative futex waits. Caught signals report
EINTR; signal handlers may post. Live-waiter destruction reports EBUSY, count
overflow reports EOVERFLOW, and process-shared initialization reports ENOTSUP.
Named semaphores are not provided. Host ASan/UBSan and TSan checks cover the
production environment and semaphore implementations. Native evidence is
`build/test-out/posix-runtime-native-qemu.log`, including eight CPU participants,
20,000 tokens, payload handoffs, timeouts, signals, spawn snapshots and `_exit`.
Run `make zen-posix-runtime-qemu-test` to reproduce it.

`sleep` is declared in `unistd.h` and uses the existing interruptible
`nanosleep` timer path. It returns unslept whole seconds on interruption,
preserves errno after a completed wait, and accepts the full unsigned-second
range without millisecond overflow. It does not install an alarm or change
signal dispositions. `make zen-sleep-qemu-test` checks eight pinned CPUs,
one-second waits, sixteen signal interruptions with and without SA_RESTART,
UINT_MAX durations and zero waits. The host sanitizer contract also checks
fractional remaining time, timer failures and chunked large durations.

`sched.h` exposes scheduler yielding and current CPU queries through the real
native thread syscalls. The C++ fixture checks both after pinning workers to all
eight CPUs. This does not implement POSIX realtime scheduling policies.
`endian.h` provides width-preserving 16-/32-/64-bit conversions through compiler
byte swaps. `alloca.h` exposes the compiler's frame-local allocation primitive
for upstream synchronous userspace code; its storage must never escape its
current frame or be retained by asynchronous work.

## File synchronization and physical memory queries

`fsync` is implemented for regular files in the process-owned descriptor
profile used by the upstream port. A registered request retains the open
description and runs the existing AlixFS node/ancestor writeback, metadata
commit and device flush on a protected storage worker. It preserves the shared
file offset; storage failure becomes EIO. Pipes, TCP sockets, audio and console
descriptions reject synchronization with EINVAL. Invalid slots return EBADF.
Legacy global descriptors return ENOTSUP and never alias private descriptors.
Directory descriptors and directory synchronization remain unsupported.

`sysconf(_SC_PHYS_PAGES)` returns the boot E820 usable RAM page count before
kernel reservations; `_SC_AVPHYS_PAGES` returns the current PMM free count.
Both use native 4096-byte pages. The total is stable across allocation; available
pages are a locked snapshot and can change immediately after the call.
`MADV_WILLNEED` is a checked, content-preserving optional performance hint;
Alix has no prefetch policy to apply. Unmapped or unaligned ranges still fail.

`ftruncate` now resizes owned regular files through registered protected-storage
requests. Shrinking preserves the prefix, growth is zero-filled, and every
shared description keeps its existing offset. Read-only descriptions return
EBADF, unsupported stream kinds return EINVAL, and callback-backed nodes are
not invoked. Allocation failure leaves the original size/content intact. A
conservative bound protects mounted AlixFS's 32-bit chunk format; seek offsets
remain 64-bit. Legacy global-descriptor profiles return ENOTSUP.

`realpath` resolves the actual VFS namespace, including symlinks before dotdot
and a captured owned cwd. Its input and work buffers are heap-owned; only the
live caller copies the final result. NULL output allocates a PATH_MAX buffer;
undersized raw replies and invalid/read-only destinations fail. `rmdir` uses a
directory-only check under the same tree lock as removal. It cannot remove a
regular file after a separate stat/lookup race; nonempty directories, mount
points and root are protected.

`make zen-filesystem-primitives-qemu-test` checks these operations on eight
CPUs, including concurrent zero-fill/read snapshots and shared alias offsets.
The actual Gecko-vendored Rust libc fixture also calls them. The existing
AlixFS two-boot test now adds a file shrunk from six to three bytes, regrown to
8192 bytes, synced and read back with its zero-fill intact after remount.
The upstream Rust File/OwnedFd, directory/path and pipe backends now use the
native libc boundary and pass `make zen-rust-runtime-qemu-test` in eight-CPU
Alix. Unsupported Rust permission/time mutation, copying, link creation and
recursive removal still report errors explicitly.

New `struct stat` records are 88 bytes and add device/inode/link identity,
owner/group, preferred I/O size and a size-based 512-byte block count. The public
stat/lstat/fstat declarations bind to `alix_stat_v2`, `alix_lstat_v2` and
`alix_fstat_v2`. Original ELF symbols keep their 40-byte records for installed
programs and the current Rust std backend. The native owned profile obtains
full replies directly through checked kernel copying; the global-descriptor
profile retains its older size/type/timestamp result with zero extra fields.
The actual Gecko Rust libc bindings use the new layout and versioned symbols.

`fchown` now changes owned regular-file credentials through protected storage
requests. It preserves identity/content and supports the unchanged-field
sentinel. Caller authorization and independent disk readback are covered by
the [VFS identity and ownership tests](vfs.md#file-identity-and-ownership).
`fchmod` now changes/persists basic `0777` bits for an owned regular file, with
owner/root authorization and captured heap requests. File-type bits are ignored;
set-ID/sticky modes fail explicitly until their policies exist. The authorization
matches the owner/superuser rule in the [fchmod reference](https://man.openbsd.org/chmod.2).
The native C/Rust fixture checks mode `0640`, and the separate-boot disk fixture
reads it back. Full path-search enforcement remains work.

Owned-descriptor `open`/`creat` and `mkdir` now apply their requested basic
permission bits and the process creation mask under the VFS tree lock. Mode
and owner initialization complete before another lookup can observe the inode.
An initial descriptor remains usable when its newly created inode has mode
zero. Existing inodes retain their permissions. `chmod(path, mode)` uses an
owned path request, so changing a mode does not require first opening the file
for reading. Set-ID/sticky policies remain unsupported.

`umask` atomically exchanges the process-wide low nine mask bits. Threads share
that state; spawn captures it with its owned launch context, applies it to file
actions and transfers it to the child. The initial mask remains zero. Named
shared-memory creation applies the same mask. New C headers bind `open` to
`alix_open_v2`, which consumes the creation mode argument. The older `open` ELF
symbol keeps the default `0666` contract for installed binaries. New source must
supply a third argument with `O_CREAT`; in-tree callers and native Rust bindings
have been updated.

`mkstemp`, `mkostemp`, `mkstemps`, `mkostemps` and `mkdtemp` use kernel entropy
and exclusive creation. File/directory modes start at `0600`/`0700` and are
restricted by the current mask. Descriptor admission precedes file creation.
`make zen-creation-modes-qemu-test` verifies eight-CPU creation, 128 unique
temporary inodes, mask exchanges/inheritance, spawn actions, zero permissions,
path chmod, shared memory, the older ABI and descriptor exhaustion. Host
sanitizer tests cover collisions, suffix/flag validation, entropy failures and
VFS ownership/concurrent mutation.
Native C fcntl byte-range locks and utimes have separate acceptance below.

Owned-profile flock now supplies shared/exclusive whole-file advisory locks,
nonblocking attempts and allocation-free unlock. Open-description ownership
survives dup and inheritance; separate opens conflict across CPUs/processes.
Pending event-driven acquisitions use cancellable reservations and live-caller
commit. Native C and Rust tests cover close/reuse, rename, signal interruption
and killed-owner cleanup. See [whole-file locks](flock.md) for conversion,
retirement and the separately implemented process-owned byte-range locks.

`utimes` captures a path and optional pair of 16-byte timevals in registered
storage requests. Explicit times require owner/root; NULL selects the current
time and also permits a nonowner with write access. The filesystem stores whole
seconds, rounding down microseconds. Invalid fractions/pre-epoch seconds fail;
old mounted formats without timestamp storage return ENOTSUP. Content and mode
are unchanged. The independent disk fixture now reads back explicit access and
modification times, and actual Gecko Rust libc calls utimes and the 24-byte
record-lock API in Alix.

Owned-profile `mkdir` uses a registered heap-owned path/cwd/credential request
and one VFS tree transaction. Existing files, directories and symlinks return
EEXIST; racing callers cannot both create the same leaf. Kernel boot/shell
callers retain the older create-or-return helper. Native mode/ACL enforcement
is still absent; the mode argument does not enable Unix permission enforcement.

The Gecko-vendored Rust libc now declares Alix's native errno and signal
numbers, __errno_location, POSIX int-returning strerror_r and kill. The actual
Rust errno crate selects its upstream implementation with these native
declarations. Eight-CPU guest checks compare constants with compiled Alix C
headers, verify matching C/Rust errno addresses and isolation, error formatting,
and kill's identity/error results. Glean's real FD logger and kvstore's path
module also execute against this boundary. This does not establish process
creation or a running XPCOM process service.

Owned-profile `ioctl` now supports FIONBIO, FIONREAD, FIOCLEX and FIONCLEX using
native checked arguments and descriptor ownership. Legacy ioctl returns
ENOTSUP. Eight-CPU pipe/file/TCP tests and the actual Rust libc ABI fixture
pass; unknown/TTY requests still report ENOTTY. See
[descriptor controls](ioctl.md) for snapshot, alias and copy semantics.

`make zen-gecko-os-interfaces-qemu-test` runs eight pinned callers, file/alias
and unsupported-descriptor checks, physical backing accounting, advice-content
checks, and two separate Alix boots with a disposable 64 MiB AlixFS disk.
The second boot reads the complete 64 KiB payload and metadata from the snapshot
taken before any guest shutdown. This is VM remount evidence, not a physical
power-loss test. The complete production AlixFS host contract also exercises
old root names, foreign parent IDs and failed-write retry.

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
