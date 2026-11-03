# Owned whole-file advisory locks

`flock` is available to the owned-descriptor libc profile through `sys/file.h`.
`LOCK_SH` and `LOCK_EX` acquire shared or exclusive whole-file locks;
`LOCK_NB` returns EWOULDBLOCK instead of waiting. `LOCK_UN` releases a lock.
This is advisory: ordinary file I/O does not consult the lock state.
Only owned regular-file descriptions are supported; console, pipe, TCP and
other adapters return EOPNOTSUPP. Invalid modes return EINVAL and invalid slots
return EBADF. The syscall takes the fd and scalar flags; remaining arguments
must be zero.

Locks belong to an open description. Duplication and inherited descriptors
share one owner; independent opens conflict even within one process. The key
is the retained VFS node, so renaming the path does not change identity.
Final description retirement releases the hold. A zero-reference description
does not block a new acquisition while its finalizer waits in the retirement
queue. Completed acquisition requests release their target pin in the live
return path, including failed try-locks. Admission, registration and submission
failures also abort their lease before leaving the preparation guard. Active I/O pins still retain their
description until that operation releases its ownership.

Mode conversion releases the old mode before waiting for the new one. A failed
nonblocking upgrade therefore does not preserve the old shared hold. Calls on
one description serialize while an acquisition is pending. Explicit unlock
supersedes a pending/unclaimed acquisition on that same description, which
returns ECANCELED. Unlock is allocation-free and bypasses event admission, so
queue saturation cannot prevent an owner from releasing its lock.
New acquisitions may fail with EAGAIN/ENOMEM when request or retirement
admission is exhausted; no held lock is fabricated on admission failure.

## Wait and cancellation ownership

`io_flock_state_t` is embedded in the regular-file context and registered only
when locking is first used. The state has a weak self pointer; its registry
lock also serializes unlink in the file's final-close callback. Readers never
retain that pointer outside the registry lock or try to resurrect it.
`fd_description_referenced` is a borrowed finalization query under this
external lifetime guard, not a new ownership acquisition.

Each acquisition creates a heap-owned deferred lease that pins the original
description and its embedded state. The syscall registers that lease in its
existing I/O cleanup record before waiting. The event executor performs bounded
nonblocking steps; a conflicting lock never occupies a storage worker.

When a lock becomes available, the event worker reserves it and publishes a
separate owned result reference. Only the live caller, under its preparation
guard and after taking a noncancelled result, commits the reservation into a
held lock. A killed or interrupted caller cannot adopt it later. Unclaimed
reservations roll back on protected cleanup. The live failure path also aborts
its completed lease immediately, preventing an old failed operation's pin from
delaying a later last-close release. No worker retains a caller process pointer,
stack address or user buffer.

## Evidence and limits

`make zen-flock-qemu-test` runs eight pinned CPUs through 256 read/modify/write
critical sections on independent descriptions. It also checks shared/exclusive
conflicts, nonblocking conversion, duplicate and final-close ownership, rename,
native child inheritance, descriptor close/reuse, signal interruption, storage
progress during contention and release of a killed waiter's held sibling file.
The native log is `build/test-out/flock-native-qemu.log`.

The upstream Rust `File` lock/try-lock/shared/unlock APIs call this real libc
interface. `make zen-rust-runtime-qemu-test` adds 256 pinned critical sections,
duplicate/final-close behavior, WouldBlock typing, a blocked writer woken after
shared unlock and rejection of unsupported descriptor kinds.

`tests/flock_contract_test.py` compiles the production lock, I/O request and FD
table modules together under ASan/UBSan and TSan. It checks provisional rollback,
explicit-unlock supersession, prompt close visibility after failed operations,
allocation/admission failure, unlock with full queues and 1,024 concurrent
critical sections while a cleanup thread retires transient same-file owners.
The actual syscall preparation function is also checked with failed admission
and submission while cleanup is deliberately delayed. Its retirement counters
must return to zero.

NSPR's Alix selector now chooses its existing BSD flock implementation, and
Gecko-vendored Rust libc declares the native function/constants. NSPR's complete
unix.c compilation and full NSPR runtime now have separate native acceptance.
These results do not prove a complete Gecko link or a running Zen browser.

## Process-owned byte-range locks

`fcntl` now implements F_GETLK, F_SETLK and F_SETLKW using the native 24-byte
flock record: int64 start/length, int32 PID and int16 type/whence. This registry
is separate from BSD flock. Regular-file locks belong to the process's FD table;
independent opens/duplicates share that owner, while native spawned processes
do not inherit its locks. Closing any descriptor for the same node releases the
process's ranges. Dup2 replacement and final table shutdown notify the registry
outside FD-table locks. Held ranges retain a deferred file description, never a
table reference that could prevent shutdown.

Read ranges coexist; write ranges conflict with other owners. GETLK reports a
conflicting PID and absolute range, or changes only type to UNLCK. It works on
read-only descriptors too. SETLK reports EAGAIN for a conflict. SETLKW uses an
interruptible pending event request, retaining old locks until the live caller
commits. Split/merge, negative lengths, future-EOF ranges and SET/CUR/END offsets
are supported. CUR/END resolution uses the protected storage worker. These are
the process-lock rules described by the [fcntl reference](https://man.openbsd.org/fcntl.2).

All asynchronous state lives in owned heap leases. The scalar query snapshot
used before admission stays on its caller's stack and is copied into the lease;
its address is never passed to another worker. Queue pressure from completed
requests waits for cleanup before pinning the original file. A completed storage
request remains registered during event-admission waits, retaining that file
through cancellation. Active queue saturation or the 4096-record budget returns
ENOLCK; allocation can return ENOMEM. The event executor never waits on storage
or a competing lock. Deadlock-cycle detection is not implemented.

Protected cleanup releases retired records outside leaf locks. Scheduler-locked
request release never runs a wake callback: process I/O glue sends cleanup
notifications after releasing scheduler_lock, and cleanup notifies admission
waiters after reclaiming slots.

`make zen-record-lock-qemu-test` passes 512 lock rounds on eight CPUs, three
spawned children, conflict PID queries, shared/exclusive ranges, splits, relative
offsets, close-any-FD/dup2 release, killed holders/waiters, fresh event progress
and checked-copy failures. The actual Rust libc fixture verifies its ABI and
calls. `tests/record_lock_contract_test.py` executes the real registry, request
and FD-table modules under ASan/UBSan and TSan, including allocation failure,
reservation cancellation, table shutdown and 2048 threaded lock/unlock calls.
Evidence is `record-lock-qemu.log` and `record-lock.acceptance.json` in
`build/test-out`.
