# Pthreads for native upstream applications

`include/pthread.h` and `user/lib/pthread.c` provide the pthread interfaces used
by SpiderMonkey's POSIX thread backend. This is an Alix ABI over the existing
kernel primitives, not a Linux pthread binary layout or a host library.

Supported operations include thread create/join/detach/self/equal/exit, stack
size and detach attributes, normal/recursive/error-checking mutexes, condition
variables, once initialization, generation-checked thread-specific keys, native
stack metadata, thread names, read/write locks, `pthread_sigmask` and
`pthread_kill`. Functions return positive error numbers.

## Thread ownership and return values

Thread IDs are native 64-bit TIDs. Pthread-created threads have a heap-owned
control record with independent creator, child, registry and join-operation
references. The child waits for publication before invoking the callback, so it
cannot complete and free the record before the creator publishes its ID.
Attributes are copied before creation; no pointer into the creator's stack is
retained. Callback arguments and shared synchronization state must themselves
be heap-owned or static, as required by Alix's stack-ownership rules.

Callbacks return a complete `void *` through the control record. The kernel's
integer thread status does not truncate it. Join/detach claims serialize under
the registry mutex. Detached records are removed after callback/TLS cleanup;
memory is freed only after the last reference is released, outside that mutex.
Returned pointers must not refer to the exiting thread's stack or TLS storage.

The initial thread uses process-lifetime static control storage. `pthread_exit`
publishes its pointer result and lets other threads continue. TLS destructors
run before the exit record is completed. After user cleanup and reference
release, `sys_thread_prepare_exit` selects the last live cleanup participant;
that participant calls libc `exit(0)` for process callbacks, while other threads
use the native thread-exit syscall. Ordinary `main` return retains process-wide
exit semantics. This follows the distinction between thread termination and
last-thread process cleanup in the [POSIX pthread_exit contract](https://man7.org/linux/man-pages/man3/pthread_exit.3p.html).

Pthread lifecycle records cover pthread-created threads and the initial thread.
Name/attribute/TSD/self operations also work with native Alix threads. Joining
or detaching foreign `alix_thread_create` handles through this facade is not
provided; native APIs retain ownership of those handles.

## Attributes and synchronization

The default stack is 256 KiB; `PTHREAD_STACK_MIN` is 16 KiB. Sizes are passed to
the real kernel stack allocator and rounded to pages there. The existing
allocator reserves one guard page: requested nonzero sizes up to one page are
supported, while zero/larger guards and caller-supplied stack memory return
`ENOTSUP`. `pthread_getattr_np` reports actual stack bounds and guard size, with
the main stack's real guard page as well. Names are real
kernel metadata with a maximum of 31 bytes plus NUL; longer names return
`ERANGE` rather than silently succeeding.

Mutexes use the native blocking gate plus owner/depth tracking. Recursive locks
retain ownership until the final unlock; error-checking locks detect self-lock
and wrong-owner unlock. Destroy rejects a locked mutex or active waiter.
Condition waits release/reacquire the supplied mutex and retain waiter counts
through reacquisition. The application must loop on its predicate. A recursive
mutex must be held exactly once when entering a condition wait.

Condition attributes select realtime or monotonic absolute deadlines. Current
conversion uses native relative futex waits, rechecking realtime at most every
100 ms and rechecking clock/sequence after timeout. The mutex is reacquired even
on expiration. A kernel absolute-deadline wait is still needed to eliminate
the clock-query-to-wait preemption gap described in the [POSIX timed-wait rationale](https://man7.org/linux/man-pages/man3/pthread_cond_wait.3p.html).

Process-shared synchronization, robust mutex recovery, priority protocols,
cancellation and caller-provided stacks are not implemented. Unsupported exposed
attributes report errors; absent facilities are not successful stubs. Once and
TSD use Alix's native implementations. Cancellation-specific once/reset and
condition cleanup remain part of future cancellation support.

## Signal masks and delivery

`pthread_sigmask` updates the calling thread's native blocked mask through the
same kernel registry used by `sigprocmask`. `pthread_kill` targets a native TID
in the same process, including the initial thread; signal zero probes existence.
Dispositions are process-wide. New threads inherit the creator's mask but not
its alternate stack or active handler frames. Unlike the libc signal wrappers,
these pthread functions return positive error numbers directly.

Caught signals may execute on the receiving thread at syscall return or from a
timer-preempted user instruction. Masked signals remain queued and standard
signals coalesce. `sigaltstack` supports a per-thread alternate stack; registration
and query use the actual user stack pointer, including a context whose RSP was
edited by a handler. The full native ABI and remaining limits are in
[signals.md](signals.md).

Native futex interruption does not turn mutex/once/publication waits into failed
ownership acquisition: the user runtime retries them. Timed condition waits
retain their deadline through EINTR and reacquire the mutex before returning.
These are not async-signal-safe lock operations; a handler must not reacquire a
lock held by the interrupted code. A registered I/O request defers caught
signal delivery until its result is consumed. Thread cancellation, nonlocal
handler unwinding and general I/O interruption are separate unimplemented
facilities.

## Read/write locks

`user/lib/pthread_rwlock.c` supplies initialization/destruction, read/write
acquisition, try variants, unlocking and process-private attributes. Shared
attributes return `ENOTSUP`; timed rwlock functions are not currently exposed.

Writers wait in FIFO order. A newly arriving reader queues when a writer is
pending, while a thread already holding a read lock may acquire it recursively.
Each completed writer admits a finite cohort of readers already waiting at that
point before the next writer. Later arrivals cannot extend that cohort while a
writer is queued. This alternates waiting classes without starving writers or
readers, assuming holders release their locks and scheduled threads make progress.

Ownership and waiter records reside on the heap, with a thread-local list and
one reusable spare per thread. No waiter record comes from a process stack.
Queue changes, counters, cohort membership and condition predicates share the
same native gate. The wait operation releases that gate and reacquires it on
return; every wake rechecks the predicate. Wait failures and queued-thread
cleanup remove the owned queue record and any cohort reservation before freeing
it, so a canceled head or cohort member cannot strand later waiters.

Reader depths and aggregate/waiter counters are checked before incrementing.
Resource exhaustion returns `EAGAIN`; blocking write recursion, write-to-read
recursion and read-to-write upgrades return `EDEADLK`. Try variants report
`EBUSY` for an unavailable lock. Unlock requires the calling reader's ownership
record or the current writer TID, otherwise returning `EPERM`. Destroy reports
`EBUSY` while holders or waiters remain. As with other pthread objects, callers
must coordinate destruction with threads that might begin a new operation.

These locks are not robust: exiting while holding a lock leaves it held. TLS
cleanup reclaims ownership metadata, not protected application state. Queue
cleanup is tested independently, but it does not advertise a general
`pthread_cancel` facility or async-signal-safe lock operations. Future
cancellation support must unwind the internal gate before invoking queued-record
TLS cleanup; the current cancellation model exits from the unlocked wait phase.

## Validation

`tests/pthread_contract_test.py` executes the production implementation with
deterministic syscall interleavings. It forces child completion inside the
creator's publication wake, join failure/claim restoration, detach races,
creation failure, pointer returns, initial-thread exit selection, owner checks
and backward-clock deadline rechecks. It also runs with ASan/UBSan through the
existing `HOST_CC` test override.

`thread_pthread_test.elf` exercises eight explicitly placed CPUs, mutex/condition
handoff, 1024 protected increments, once, TLS keys/destructors, names and stack
queries, 128 fast joins, and 32 detached-thread reclamations. It requires
`THREAD_PTHREAD_TEST: main PASS` followed by `THREAD_PTHREAD_TEST: exit PASS`.
Its `initial-exit` mode joins the original thread from a worker, verifies its
full pointer return, and requires a surviving worker to trigger the final
`THREAD_PTHREAD_TEST: initial-exit PASS` process callback.

`tests/pthread_rwlock_contract_test.py` executes the actual implementation with
concurrent blocking-primitive models, including FIFO/cohort ordering, recursive
owners, waiter failure/cancellation, resource limits and 12,000 mixed operations.
Plain, ASan/UBSan and TSan checks pass. The native
`build/user/thread_rwlock_test.elf` fixture uses eight pinned CPUs and requires
`THREAD_RWLOCK_TEST: PASS cpus=8 writes=1024 recursion=1 fifo=1 cohorts=1` before
claiming that the new read/write-lock execution gate is verified.
That marker is now present in `build/test-out/thread-rwlock-qemu.log` from the
eight-CPU Alix guest, with shell recovery and no unexpected faults.

The native signal fixture also passed on all eight CPUs with 96 worker
handler invocations, masks/coalescing/unblock delivery, `pthread_kill`, nested
alternate stacks, migration during an active handler, edited RSP, and interrupted
`nanosleep`. Its normal/default/bad-frame evidence is in
`build/test-out/signal-kernel-{normal,default,badframe}-qemu.log`; see
[signals.md](signals.md) for the exact checks. This is additional signal-path
proof, not a claim that cancellation or in-flight I/O interruption is complete.


## ISO C11 threads

`include/threads.h` and `user/lib/threads.c` expose all 25 C11 operations over
this native pthread lifecycle. Thread callbacks and full signed integer returns
are adapted through heap-owned start records. Once, TSS/destructors, condition
variables and plain/recursive/timed mutexes use the same native ownership and
blocking primitives. C11 status codes are mapped independently of errno.

Timed mutex acquisition retries the native try-lock after bounded sleeps and
rechecks the TIME_UTC deadline after every wait or signal interruption. Condition
variables use the existing realtime timed-wait path and always reacquire their
mutex. `thrd_sleep` distinguishes interruption (-1) from other failure (-2).
The last thread retains normal process-finalization semantics through pthread's
existing native cleanup selection. C11 adds no cancellation requirement.

The native libc acceptance fixture covers eight pinned CPUs, once, TSS
isolation/destructors, signed returns and explicit exit, condition handoff,
recursive/try/timed locks, detach, sleep and FP-state isolation. See
[libc.md](libc.md) for the required runtime markers and test scope.
