# Pthreads for native upstream applications

`include/pthread.h` and `user/lib/pthread.c` provide the pthread interfaces used
by SpiderMonkey's POSIX thread backend. This is an Alix ABI over the existing
kernel primitives, not a Linux pthread binary layout or a host library.

Supported operations include thread create/join/detach/self/equal/exit, stack
size and detach attributes, normal/recursive/error-checking mutexes, condition
variables, once initialization, generation-checked thread-specific keys, native
stack metadata and thread names. Functions return positive error numbers.

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
zero guards for the initial stack when reported by the kernel. Names are real
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
