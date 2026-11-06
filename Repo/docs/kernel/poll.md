# Native descriptor polling and selection

The upstream runtime provides `poll` through `include/poll.h` and
`user/lib/poll.c`. It uses the private process descriptor table, as do the native
upstream file, pipe and TCP APIs. Existing applications using global legacy
descriptor numbers keep their existing runtime. Do not combine both descriptor
namespaces in one executable.

`SYSCALL_FILE_POLL` on the existing file-I/O syscall takes an array of eight-byte
`syscall_pollfd_t` records, a count and a signed millisecond timeout. Zero returns
immediately; any negative timeout waits indefinitely. At most 256 records are
accepted, matching the private descriptor-table capacity. Negative descriptor
numbers are ignored and their returned flags are cleared. Invalid nonnegative
numbers return `POLLNVAL`. Error and hangup flags are reported even when no input
events were requested. The return value counts records with returned flags,
including duplicate records for the same description.

The preparation guard copies the caller's records, creates a deferred synthetic
description and pins each original file description before submission. The
protected event worker takes bounded readiness snapshots; it never reads a user
buffer or retains a caller's process, thread or stack pointer. The original
description remains pinned if another thread closes/reuses its integer slot.
The captured vector acquires the descriptor-table lock once for up to 256
entries, retaining a separate reference for each valid entry, including aliases.
Invalid entries remain null and become POLLNVAL; reference overflow leaves
already captured owners in the set for normal cleanup. No readiness callback,
allocation or final put runs under that lock. The capture observes one table
state even if another CPU concurrently closes/reuses slots.
Concurrent-close behavior is otherwise not a portable POSIX synchronization
mechanism. Destruction releases every pin on the retirement worker, including
after a killed waiter abandons its request.

Pipes report buffered input, hangup, missing readers and space for an atomic
`PIPE_BUF` write. TCP reports actual receive bytes, writable send capacity, EOF
and transport errors. Owned regular files/directories are immediately ready;
imported console output and null input expose their supported directions. The
owned PCM output reports space for at least one complete frame without claiming
the channel. An adapter without a readiness callback returns `POLLERR`; readiness
is never inferred by running a possibly blocking data callback. Out-of-band TCP
data and `POLLPRI` are not implemented.

Shared `F_GETFL`/`F_SETFL` status supports `O_NONBLOCK`. Native TCP connect starts
the real transport and reports `EINPROGRESS`; poll observes actual completion.
An idle read or unavailable send capacity returns `EAGAIN`. The guest fixture
checks status changes through an alias, connect/poll, an idle read, then the
complete 16 KiB response and EOF. No raw socket or POSIX socket facade is implied.

Timeouts use the kernel's monotonic clock and are checked by the event worker.
A caught unblocked signal interrupts poll with `EINTR`, including when its
handler uses `SA_RESTART`. Existing non-poll I/O retains its prior signal-delivery
behavior. `ppoll` and `pselect` remain unimplemented; there is no simulated
signal-mask swap around a wait.

Run `make`, then `make zen-poll-qemu-test`. The fixture checks real native
timeouts, pipe backpressure/hangup, regular-file EOF readiness, all eight CPUs,
16 KiB of TCP data and EOF, descriptor close/reuse, signal interruption and
release of the final pinned pipe reader after killing a blocked child. Serial
and network captures are under `build/test-out/poll-native-*`; use `tcpdump` to
inspect the packet capture. `tests/poll_contract_test.py` additionally exercises
production code under host sanitizers for allocation failure, deadline overflow,
event masking and concurrent snapshots.

## Select

The upstream owned-FD runtime now provides `select` through `sys/select.h` and
`select-owned.o`. Native `fd_set` is a fixed 32-byte, 256-bit layout matching the
private table. Its FD_ZERO/SET/CLR/ISSET operations cover descriptors 0 through
255; a caller-defined FD_SETSIZE cannot change the ABI. The ordinary legacy
runtime returns ENOTSUP rather than interpreting global descriptors as private
slots. The upstream linker verifies that exactly one owned select object is
present and excludes the legacy object.

`SYSCALL_FILE_SELECT` takes a version-1 48-byte query and its exact byte size.
The query contains nfds, zero flags and nullable read/write/exception-set and
timeval addresses. Before submission, the live caller safely copies the query,
sets and timeout into temporary heap storage. It creates an owned poll set,
captures requested masks and pins the original descriptions. Temporary user
addresses are freed before submission; workers see no user pointers or caller
stack addresses. Output destinations remain solely in the live syscall frame.
The registered request owns all waiting state and output scratch. Failed
preparation, interrupted waits and caller death use the existing ownership and
retirement paths.

The shared wait object has an explicit select mode. Input/hangup/error flags
map to read readiness, output/error flags to write readiness, and only POLLPRI
to exceptional readiness. A hangup on an exception-only wait therefore does not
complete the operation or create a libc retry loop. Invalid requested slots
become EBADF before output sets change. On success, each returned set contains
only the ready requested bits and the return value counts bits across all
sets, including one descriptor ready in multiple sets. These semantics follow
the [primary select API reference](https://man.openbsd.org/select.2).

Timevals must contain nonnegative seconds and microseconds below 1,000,000.
They round upward to the native millisecond clock, use signed 64-bit intervals
with a saturating monotonic deadline, and remain unchanged on return. Null
timeouts wait indefinitely; zero timeouts return immediately. EINTR preserves
the input sets and is not restarted by SA_RESTART. The live caller checks
output copies; inaccessible or read-only output sets report EFAULT. Priority
data/OOB still depends on transport support and is not implemented by native
TCP. There is no claim of a complete socket or POSIX profile.

`make zen-select-qemu-test` passes an eight-CPU guest with all descriptor bits,
the highest slot, multi-set counts, rounded timeouts, invalid/overflowing inputs,
safe input/read-only output copies, eight pinned waiters, close/reuse, signals,
killed-caller cleanup and 16 KiB of real TCP data/EOF. The exception-only TCP
hangup wait expires normally. Evidence and the packet capture are retained as
`build/test-out/select-native-*`. The actual Gecko-vendored Rust libc also
passes fd_set/timeval layout and select calls against Alix. Production host
poll/select contracts pass ASan/UBSan and TSan, including deadlines beyond
32-bit milliseconds and 20,000 concurrent snapshots.

## Immediate scans

A zero-timeout poll now scans its captured, heap-owned and pinned set directly
inside the bounded preparation guard. It needs no registered executor request,
waiter/result transitions or request retirement. Checked output copies, duplicate
counts, descriptor pin ownership and pending-signal EINTR behavior remain.
The `io_poll_snapshot` routine supplies the same readiness logic to the existing
registered request path for operations that may actually wait.
