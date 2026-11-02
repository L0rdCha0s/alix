# Syscalls, FDs, and Sockets

This kernel exposes a small syscall surface for user programs. Syscalls are dispatched via vector 0x80.

Syscall 74 (`MEMORY_PAGES`) takes a selector in RDI: zero returns boot E820
usable RAM before kernel reservations; one returns the current locked PMM free
count. Both results are in 4096-byte pages. Other selectors return -EINVAL;
an unready PMM returns -EAGAIN. The call accesses no user pointers.

The owned `FILE_IO` operation `SYSCALL_FILE_SYNC` takes only a private file
descriptor; other arguments must be zero. It pins that description in a
registered request and performs AlixFS writeback/commit/device flush through the
protected storage service. See [libc](libc.md) for supported descriptor types
and the separate-boot readback test.

`SYSCALL_FILE_SELECT` takes a versioned 48-byte query and its exact size;
remaining arguments must be zero. The query names nullable 32-byte descriptor
sets and an input-only native timeval. It safely captures inputs, uses the
protected event service and copies readiness back only in the live caller.
See [poll/select](poll.md) for the ABI, 64-bit timeout policy, ownership and
native validation.

`SYSCALL_FILE_TRUNCATE` takes a private fd and nonnegative signed-64-bit length;
remaining arguments must be zero. The storage request pins the original open
description, serializes its offset gate and changes node data under the data
lock without changing the offset. `SYSCALL_FILE_REALPATH` takes an input path,
output buffer and capacity up to VFS_PATH_MAX; the fourth argument is zero.
Its protected worker resolves/canonicalizes copied path bytes using a retained
cwd, then the live caller performs the checked output copy. REMOVE mode 2 is
directory-only; modes 0/1 retain the earlier unlink/C-remove behavior.

`SYSCALL_FILE_MKDIR` takes an input path and three zero arguments. A registered
storage request captures its path, cwd and uid/gid. One VFS tree transaction
creates the directory with those credentials or returns EEXIST for an existing
leaf. This strict owned-profile operation preserves the kernel helper's older
create-or-return behavior. Mode/ACL enforcement remains unimplemented.

`SYSCALL_FILE_FLOCK` takes a private fd, shared/exclusive/nonblocking/unlock
flags and two zero arguments. Acquisition uses registered heap-owned leases on
the event executor and a live-caller reservation commit. Unlock is immediate
without queue admission. See [whole-file locks](flock.md) for duplicate/close,
conversion and cancellation semantics. Byte-range fcntl locks remain pending.

`SYSCALL_FILE_IOCTL` takes fd, native request number, user pointer and payload
size. FIONBIO/FIONREAD require exactly four bytes; FIOCLEX/FIONCLEX require a
zero pointer and size. Nonblocking updates preserve unrelated status bits.
Readable-byte queries pin the original description in the existing protected
I/O services and perform checked copyout only in the live caller. See
[descriptor controls](ioctl.md) for supported backends and native validation.

Syscall 69 (`RESOURCE_USAGE`) returns a versioned 48-byte snapshot for the
current process: clock frequency, sampled user/system ticks and minor/major
fault counters. The kernel holds process ownership through a bounded guard,
releases its usage lock before copying, and rejects invalid selectors, sizes
and destinations. `getrusage(RUSAGE_SELF)` translates this into native timevals
and signed counters. `RLIMIT_AS` separately reports the current absence of an
aggregate virtual-memory quota; it does not promise unlimited physical memory.

Syscall 70 (`DIRECTORY`) opens, reads, rewinds or closes opaque per-process
directory handles. Arguments are operation, handle, user pointer and byte size.
OPEN uses a NUL-terminated path; NEXT requires a versioned 4120-byte result and
returns one entry, zero at EOF, or negative errno. CLOSE/REWIND take no pointer.
The handle namespace is separate from legacy file/socket FDs. All path lookup
and cursor work runs on protected workers with registered owned requests; only
the live caller performs user copies. See [directory streams](vfs.md).

Syscall 71 (`FILE_IO`) selects the process-owned descriptor namespace. Its
operation and four arguments use RDI, RSI, RDX, R10 and R8. It implements open,
read, write, close, pread, seek, stat, descriptor flags, duplication and the
native TCP open/connect/available interfaces. The original syscall IDs retain
their legacy global-FD ABI for installed applications. Neither namespace falls
back to the other when an integer is absent.

The upstream toolchain links `syscall-owned.o` and `fcntl.o`, while ordinary
Alix targets retain `syscall.o`. The owned wrappers translate negative kernel
errors to `-1` plus thread-local errno. `fcntl` supports F_GETFD, F_SETFD,
F_DUPFD and F_DUPFD_CLOEXEC; dup/dup2/dup3 share open descriptions and offsets
while retaining independent close-on-exec flags. `pipe`/`pipe2` atomically
publish two private descriptors backed by an event-driven byte ring; see
[pipes.md](pipes.md). File status flags and nonblocking I/O remain unfinished.

User processes have 256 private slots shared by their threads and directory
streams. Kernel-launched processes start with EOF stdin and owned stdout/stderr
descriptions. Capture imports retain their ShellService session, and private
console writes bypass the legacy global capture tap. A user-parent constructor
clones the table with CLOEXEC filtering; native user-parent exec acceptance is
still pending. Process teardown defers table retirement until quiescence.

OPEN reserves a private slot before any creation or truncation. The registered
request owns its reservation, captured cwd/credentials and copied path. Commit
installs only into that reservation; failure cancels it before returning.
Abandoned requests release their reservations through protected cleanup.
Consequently a full table cannot truncate a file and then report EMFILE.
Read/write buffers are request-owned, and only the live caller copies results
to user memory. Regular files and streams use storage workers; TCP uses the
event executor. A separate DNS service resolves hostnames while retaining the
same socket description through DNS and connect, even if its integer FD is
closed or reused concurrently.

`tests/private_fd_qemu_test.py` passed shared offsets across eight CPUs,
flags/duplication, capacity, failed-truncate preservation, 16 KiB HTTP and
isolated ShellService capture. `tests/owned_runtime_qemu_test.py` passed the
standard C descriptor/stdio API and upstream libc++/ABI plus narrow/wide
streams in separate eight-CPU guests. Callback-backed VFS nodes, shell `>`
redirection through private descriptors and general child-process APIs remain
separate gates.

Syscall 72 (`PROCESS`) adds argv launch and child waiting through protected
loader/readiness services. Its child registry is separate from public FDs.
`waitpid` supports positive PIDs, any-child selection and WNOHANG; owned claims
allow retry after bad status copyout and prevent duplicate reaping. The current
argv launcher uses an empty environment. See
[child_processes.md](child_processes.md) for lifetime and native acceptance.

`FILE_IO` also exposes `SYSTEM_INFO` and `HOSTNAME` metadata operations,
independent of either FD namespace. Protected workers own the hostname
snapshot; the live caller checks and copies the result. `PROCESS` operation 4
returns the current primary group. See [system identity](system_identity.md)
for the 325-byte uname wire format, build ID and credential semantics.

GET_LIMIT/SET_LIMIT metadata operations use a 16-byte native resource pair.
RLIMIT_NOFILE is enforced by the process's owned table across allocations and
spawn inheritance; RLIMIT_AS reports the current absence of an aggregate
address-space quota. See [descriptor limits](descriptor_limits.md).

## ABI / Entry (`src/arch/x86/syscall_entry.S`)

User code executes `int 0x80`. The IDT routes vector 0x80 to `syscall_entry`, which:

- Saves general-purpose registers onto the current stack.
- Calls `syscall_dispatch(syscall_frame_t *frame, uint64_t vector)` in C.
- Restores registers and returns with `iretq`.

## Dispatcher and IDs (`src/kernel/syscall.c`, `include/syscall_defs.h`)

`syscall_dispatch` reads:

- `RAX` = syscall number (`syscall_id_t`)
- Arguments from `RDI/RSI/RDX/R10/R8/...` depending on the syscall

Pointer safety:

- Most syscalls validate user pointers with `user_ptr_range_valid` and move data using `user_copy_*` helpers (`src/kernel/user_copy.c`).
- `user_ptr_range_valid` checks address shape only; it never authorizes a direct
  dereference. The copy helpers resolve owned physical backing and permissions
  under the current process's `memory_lock`, then copy through the kernel
  physmap. Each critical section is bounded to one 4 KiB page, and no backing
  pointer survives unlocking. Concurrent unmap/protection changes cause a false
  result on the next inaccessible page instead of a kernel page fault. A failed
  multi-page copy may already have copied a prefix.
- String copies fetch bytes once and stop at NUL without requiring the following
  page to be mapped. Write copies reject read-only mappings as well as holes and
  `PROT_NONE` ranges. Copying requires a current user process.
- Shell polling uses a call-owned kernel buffer before copyout, and the process,
  network and CPU snapshot syscalls use private heap buffers for each call so
  concurrent callers cannot overwrite or reallocate each other's snapshots.
  ATK event-poll paths report an inaccessible output buffer even when no event
  is available.

`make user-copy-contract-test` exercises page boundaries, permission checks,
between-page revocation, concurrent snapshot interleavings and copyout errors.
`user_copy_test.elf` adds native protected/unmapped syscall access and a two-CPU
protection/copy race to the QEMU validation suite.

## File Descriptors (`src/kernel/fd.c`)

FDs are kernel-managed handles with an ops table:

- `fd_ops_t` contains `read/write/close/pread/lseek/fstat`.
- Each FD table entry stores `{ ops, context }`.
- Table size is currently fixed (`FD_MAX`).

This FD layer is shared by:

- VFS-backed files (`syscall.c` wraps a `vfs_node_t` + offset in a `file_handle_t`)
- TCP sockets (`src/net/tcp.c` registers a socket with FD ops)
- Shell service sessions (`src/kernel/shell_service.c` exposes a write-only FD capturing output)

## File Syscalls (VFS-backed)

The ownership infrastructure in `fd/table.c`, `io/request.c`, `io/service.c` and
`process/process_io.c` is integrated, but the file syscalls below still use the
legacy global FD namespace. The protected executor has persistent storage
workers and an independent cleanup worker. Requests own their kernel buffers,
description pins, retained cwd and captured uid/gid; workers retain no caller
process pointer or user address. Off-CPU thread reclamation abandons a killed
caller's waiter, while a running continuation keeps all resources until it
finishes. Final request release only queues cleanup; destructors run unlocked
on the cleanup worker. Indefinite TCP waits are excluded from the finite pool.

`tests/io_service_qemu_test.py` passes the native queued/running cancellation,
independent cleanup, late OPEN-result disposal, retained service join and live
waiter shutdown cases, followed by an eight-CPU TLS fixture. It restores the
ordinary kernel image after the optional boot test. This acceptance proves
executor lifetime behavior. The newer syscall 71 acceptance above covers
regular VFS adapters and private user descriptors; cancellation during an actual
blocked AHCI operation remains a separate integration gate.

Important behavior:

- `SYSCALL_OPEN` allocates a `file_handle_t`, retains the `vfs_node_t`, then installs an FD using `fd_allocate`.
- `SYSCALL_READ/WRITE` advance `file_handle_t.offset` after successful operations.
- `SYSCALL_PREAD` reads at an explicit offset without updating the shared offset.
- `SYSCALL_LSEEK` mutates the `file_handle_t.offset` according to `SEEK_SET/CUR/END`.
- `SYSCALL_LIST_DIR` enumerates children via VFS callbacks and returns `syscall_dirent_t[]`.

## Sockets (TCP)

Socket syscalls are TCP-only today:

- `SYSCALL_SOCKET_OPEN(iface_name?)`:
  - Chooses a NIC (optional name; otherwise “first present, prefer link_up”).
  - Calls `net_tcp_socket_open(iface)` and returns the socket’s FD.
- `SYSCALL_SOCKET_CONNECT(fd, ipv4_text, port)`:
  - Validates and parses IPv4 text.
  - Calls `net_tcp_socket_connect(...)` and waits for ESTABLISHED (poll/sleep loop).
- `SYSCALL_SOCKET_AVAILABLE(fd)`:
  - Returns readable byte count in the RX buffer.

Read/write/close on the returned FD are handled by `src/net/tcp.c`’s `fd_ops_t`.

## Other Syscalls

The syscall surface also includes:

- Process and CPU snapshots (`SYSCALL_PROC_SNAPSHOT`, `SYSCALL_CPU_SNAPSHOT`)
- Network interface snapshots (`SYSCALL_NET_SNAPSHOT`)
- Time queries (`SYSCALL_TIME_MILLIS`, `SYSCALL_TIME_INFO`)
- Shell service session control (`SYSCALL_SHELL_*`)
- UI syscalls for remote ATK windows (`SYSCALL_UI_*`)
- User thread lifecycle (`SYSCALL_THREAD_*`)

### Timezone configuration snapshot

`SYSCALL_TIMEZONE_INFO` (58) accepts an output pointer and capacity. Version 1
writes the 328-byte `syscall_timezone_info_t` without changing the older
`SYSCALL_TIME_INFO` ABI. It returns a configuration generation and fixed,
rule-based or IANA kind; offsets are seconds east of UTC. Monthly rules include
month/week/weekday, transition seconds and an explicit wall-clock basis. Zone
identifier and display name are separate bounded strings. A display name is
not an abbreviation table and the IANA kind does not supply TZif transitions.

Publication and snapshot copying share the timezone lock, so fields and
generation come from one configuration. The syscall builds its wire structure
in private heap storage, defers preemption while owning it, and uses safe
copyout before freeing it. IRQ delivery remains enabled. Short capacity returns
`-EINVAL`, an inaccessible destination returns `-EFAULT`, and allocation failure
returns `-ENOMEM`. `tests/timezone_snapshot_test.py` covers concurrent publication,
wire layout, initialization and failure cleanup under sanitizers. This snapshot
supplies configured rules or a data identifier; historical timezone conversion
still needs the user library's timezone implementation and its data files.

## Native signals and interruptible sleep

These are native Alix calls, not Linux signal layouts. Public libc wrappers
convert negative status to `errno` where required; pthread signal wrappers
return positive error numbers. The shared version-1 wire types are in
`include/signal_abi.h`; [signals.md](signals.md) describes ownership, context
validation, limits and native acceptance.

| ID | Interface | Contract |
| --- | --- | --- |
| 59 | `sys_sigaction(number, action, old, size)` | Read/install a process disposition; action wire size must be 24. Nullable action/old pointers select query/update. |
| 60 | `sys_sigprocmask(how, set, old)` | Update the caller's 64-bit mask with BLOCK=0, UNBLOCK=1 or SETMASK=2; PENDING=3 with null set snapshots queued signals. |
| 61 | `sys_sigaltstack(stack, old, size)` | Query/update a 24-byte alternate-stack descriptor; changing a stack currently used by the caller returns `-EPERM`. |
| 62 | `sys_sigreturn(frame_address)` | Validate and restore the current thread's top signal frame; successful return resumes its saved/edited user context. |
| 63 | `sys_raise(number, tid)` | Queue to a same-process native TID; tid=0 selects the caller. Signal zero probes target existence. |
| 64 | `sys_kill(pid, number)` | Post to a positive user PID with ownership checks; group/job-control forms return `-ENOTSUP`. |
| 65 | `sys_sleep_interruptible(milliseconds, remaining)` | Wait with signal interruption; optional remaining output is captured before delivery and bounded by the original milliseconds. |

Unmasked pending signals deliver at full syscall return frames and timer-preempt
SYS_YIELD returns. The latter reconstruct the original user PC/RSP and GPRs from
the red-zone-preserving stub. Native sigreturn bypasses the ordinary result
assignment and restores validated GPRs/flags/x87/SSE state. Demand-zero and
main-stack page-fault recovery remain ahead of hardware signal delivery.

Caught signals defer while a registered I/O request still owns an operation;
they do not invoke destructive caller-abandonment cancellation. General I/O
EINTR/restart semantics remain separate work. Syscall 36 retains its previous
sleep behavior; libc `nanosleep` uses call 65 and clamps rounded remaining time
to the original request. Normal, default and bad-frame native signal fixtures
passed in eight-CPU guests; exact evidence is recorded in [signals.md](signals.md).

## Thread-local storage and blocking waits

The following native interfaces support future hosted runtimes; they do not
claim Linux/POSIX syscall compatibility.

| ID | Interface | Contract |
| --- | --- | --- |
| 41 | `sys_thread_set_tls(base)` | Set this user thread's x86-64 FS base; zero clears it. Reject noncanonical/kernel/out-of-window addresses. Returns 0 or -1. |
| 42 | `sys_thread_get_tls()` | Return the current user thread's FS base. |
| 43 | `sys_futex_wait(address, expected, timeout_ms)` | Wait on a process-private aligned 32-bit word if its current value matches `expected`. |
| 44 | `sys_futex_wake(address, max_waiters)` | Notify at most `max_waiters` matching waiters in this process; return the count. |
| 45 | `sys_monotonic_millis()` | Milliseconds since timer initialization, independent of wall-clock/NTP adjustments. |
| 46 | `sys_thread_set_affinity(cpu_index)` | Pin the current user thread to an online CPU; `UINT32_MAX` clears explicit affinity. Returns 0 or -1. |
| 47 | `sys_thread_cpu()` | Snapshot the current CPU index. |

FS-base updates disable local interrupts while changing the saved thread state
and hardware MSR. Scheduler save/restore preserves it across context switches.
Normal ELF process/thread creation initializes native static variant-II `PT_TLS`
storage before entry: the template is copied, TLS BSS is zeroed, and FS points
to the thread control block with its self pointer at FS:0. C/C++ thread-local
storage, thread-local errno and TLS destructor cleanup are implemented.
The raw setter is an explicit override: it checks address shape, not mapping or
TCB contents. Callers must preserve/restore the runtime's native base around
such an override and must not free storage while a thread still references it.

Setting affinity uses the existing scheduler's ownership-transfer path and
yields outside locks before returning. It does not alter the process defaults
or other threads' affinity. The TLS test migrates each of eight workers across
all eight CPUs; the synchronization test pins four workers to distinct CPUs.

Futex wait returns `SYSCALL_FUTEX_OK` (0), `AGAIN` (-11) for a value mismatch,
`FAULT` (-14) for an unmapped word, `INVALID` (-22) for an invalid/misaligned
address, `INTERRUPTED` (-4) for an unblocked pending signal, or `TIMED_OUT` (-110).
Timeouts are relative milliseconds: zero checks
without blocking, and `SYSCALL_FUTEX_WAIT_FOREVER` waits without a deadline.
Wake validates the address form and uses it as a key without dereferencing it.

Expected-value comparison and waiter registration serialize with wake under
the scheduler lock. The memory helper reads owned physical backing while
holding the process memory lock, avoiding an unchecked kernel dereference of
the user pointer. Once registered, notification predicates touch only state
embedded in the heap-owned kernel thread. Wake-before-sleep is retained; process
termination uses the existing wait/sleep queue cleanup.

User libc now provides `alix_cond_init`, `alix_cond_wait`,
`alix_cond_timedwait`, `alix_cond_signal` and `alix_cond_broadcast`. A valid wait
releases and then reacquires the caller's mutex, including on timeout/error.
The application must check its predicate in a loop. Shared mutexes, conditions
and thread arguments must be heap-owned or static, never on another thread's
stack. Do not reinitialize or free synchronization objects while in use.
Condition APIs return status codes directly rather than setting thread-local
errno. Interrupted mutex/once waits retry; timed condition waits recompute their
remaining deadline and always reacquire the mutex. `alix_mutex_t` retains its
single-word layout; contention blocks through the futex interface.

Validation: `make futex-contract-test`, `make thread-platform-test`, and
`make thread-platform-qemu-test` (isolated native Alix guests).

