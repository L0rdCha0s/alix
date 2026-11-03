# Native signals and user fault delivery

Alix now delivers hardware faults and queued signals through its native kernel
signal registry. `include/signal.h`, `include/signal_abi.h` and
`include/sys/ucontext.h` define the user ABI; `user/lib/signal.c` provides libc
and pthread wrappers. `src/kernel/process/process_signal.c` owns dispositions,
pending delivery, frame construction and validated return. This replaces the
former private libc callback array.

The normal, default-termination and unusable-frame fixtures have passed in
isolated eight-CPU Alix guests. This establishes native signal execution; it
does not establish that SpiderMonkey or Zen runs. The upstream Wasm bridge and
remaining browser integration are separate work.

## Registration, masks and delivery

`signal`, `sigaction`, `raise`, `kill`, `sigprocmask`, `sigpending`, `sigaltstack`,
`pthread_sigmask` and `pthread_kill` use the same registry. Dispositions belong
to the process. Masks, alternate stacks, pending thread signals and active frame
chains belong to threads. A new user thread inherits its creator's blocked mask
when created in the same process; it starts without an alternate stack or active
handler frame.

`sigset_t` is a 64-bit native mask. Signal number n uses bit n−1, with numbers
1–31 accepted by the mask helpers. Job-control operations for numbers 18–22
return `ENOTSUP`; they do not implement stop/continue behavior. `SIGKILL` cannot
be caught or blocked. `SIGSTOP` is also removed from supplied masks even though
job control is not implemented. Invalid numbers, unsupported action flags and
`SIG_ERR` as a handler are rejected.

An action contains the handler/three-argument callback union, mask and flags.
The supported flags are `SA_SIGINFO`, `SA_NODEFER`, `SA_ONSTACK`,
`SA_RESETHAND` and `SA_RESTART`. During delivery the action's mask is added to
the interrupted mask; the delivered signal is also blocked unless `SA_NODEFER`
is set. `SA_RESETHAND` resets the selected disposition atomically under the
scheduler lock, before frame allocation. A concurrent later registration is
not erased when that frame is published. No registry lock is held while user
code runs. `signal()` installs a persistent handler with `SA_RESTART`.

Standard pending signals coalesce; the first pending information for a signal
is retained. `raise` targets the caller; `pthread_kill` targets a native TID in
the same process. `kill` accepts a positive user PID, subject to ownership/root
checks, and selects an eligible thread or leaves a process-pending signal when
all threads block it. Signal zero is a target-existence probe for the raw target
interfaces. Process-group forms return `ENOTSUP`. `sigpending` snapshots the
union of the caller's and process's queued signals.

Caught pending signals deliver at a full syscall return frame, including the
timer-preemption `SYS_YIELD` path. Ignored dispositions discard queued signals.
The default actions for `SIGCHLD`, `SIGURG` and `SIGWINCH` ignore them; other
implemented default actions terminate the whole process with status
`128 + signal number`, without libc exit callbacks. `abort()` unblocks and raises
`SIGABRT`; an ignored disposition or returning handler is followed by raw process
exit with status 134.

## Synchronous signal waiting

`sigwait(set, number)` uses native syscall 75. The requested set must be blocked
in the calling thread. The kernel atomically accepts one pending signal from the
thread or process and writes its number as a four-byte integer. Standard signals
coalesce, and competing waiters accept each queued signal at most once. Acceptance
does not run a handler, reset its disposition, or change the caller's mask.

The syscall captures the eight-byte input mask before registering the wait. Its
embedded queue and mask belong to the heap-owned thread. Registration, pending
selection and sender wakeup share the scheduler lock; no worker retains the
caller's output pointer. A checked output copy precedes pending-bit consumption,
so `EFAULT` preserves the selected signal. Termination removes the waiter without
making an exited thread runnable again.

The libc function returns zero or a positive error number and preserves `errno`.
An unrelated caught signal interrupts the internal wait; libc retries after its
handler returns. Empty, unknown, unsupported job-control or unblocked requested
sets return `EINVAL`; bad user memory returns `EFAULT`. `SIGKILL` and `SIGSTOP`
are removed from the set. Existing ignored-signal behavior is unchanged: ignored
signals are discarded, so callers should install a disposition before waiting
for one of those signals. `sigwait` can also wait inside an NSPR-style signal
handler whose action mask blocks the requested signal.

The acceptance and competing-waiter behavior follows the
[sigwait interface contract](https://man.openbsd.org/sigwait.3). Timed signal
waiting and `sigsuspend` remain separate work.

`make zen-sigwait-qemu-test` passed in an eight-CPU guest. Its
`build/test-out/sigwait-qemu.log` records 512 directed waits, eight competing
process waiters, coalescing, protected and cross-page output failures, argument
validation, preserved dispositions/masks/errno, unrelated-signal retry, nested
handler waiting and killing a blocked waiter. Gecko's actual vendored Rust libc
also passes mask layout, block/raise/wait and mask restoration in
`rust-libc-ffi-native-qemu.log`. These are component results; complete NSPR and
Zen startup remain unverified.

## Hardware faults and editable contexts

Exception entry preserves all 15 general registers and the CPU return frame.
Demand-zero, heap and main-stack page-fault recovery run before signal delivery.
A recovered allocation fault therefore does not invoke a SIGSEGV handler.
Unrecoverable user #PF/#GP/#SS faults select SIGSEGV, #UD selects SIGILL and #DE
selects SIGFPE. Kernel faults retain the kernel-failure path. An ignored, blocked
or unusable handler for a synchronous fault terminates the process instead of
repeatedly executing the same faulting instruction.

SIGSEGV classification uses logical mapping ownership, not only the x86 present
bit. A `PROT_NONE` reservation or forbidden write to a discarded read-only mapping
is `SEGV_ACCERR`, even with a nonpresent PTE. An unowned address, main-stack guard
or address above the allocated heap break is `SEGV_MAPERR`.

The version-1 x86-64 structures are native Alix structures:

| Structure | Size | Relevant layout |
| --- | --- | --- |
| `sigset_t` | 8 bytes | 64-bit signal mask |
| Action wire | 24 bytes | Handler u64, mask u64, flags/reserved u32 |
| `stack_t` | 24 bytes | Pointer, size, flags and reserved word |
| `siginfo_t` | 64 bytes | Signo/code, address, PID/UID/TID and hardware vector/error |
| `mcontext_t` | 704 bytes | Named GPRs, RIP/CS/RFLAGS/RSP/SS, trap/error/CR2, then 512-byte FXSAVE64 at offset 192 |
| `ucontext_t` | 768 bytes | Version/size, flags/link, mask/stack snapshot; `uc_mcontext` at offset 64 |
| Private signal frame | 896 bytes | Ownership header, siginfo and ucontext |

`ucontext_t.uc_mcontext.rip`, `.rbp` and `.rsp` are aligned 64-bit lvalues suitable
for the explicit Alix Wasm context bridge. The handler may edit general
registers, RIP/RSP, permitted flags, signal mask and valid FXSAVE64 state before
return. The alternate-stack field is a snapshot, not a `setcontext` interface.
There is no Linux `gregs[]` layout or Linux sigreturn ABI.

Handler entry uses the SysV stack alignment, clears DF and protects the
interrupted 128-byte red zone. An RX restorer at offset `0x200` in the first
existing user stub page calls native sigreturn; offset `0x100` remains the
thread-exit stub. The user preemption stub also protects the red zone. Its
73-byte instruction sequence returns from int80 at +38 and uses `ret 128`.
Delivery from this path reconstructs the original instruction and register order
from the 264-byte saved area, rather than reporting a stub instruction as the
interrupted user PC.

## Alternate stacks and ownership

`MINSIGSTKSZ` is 16 KiB and `SIGSTKSZ` is 64 KiB. Registration checks range/size;
an inaccessible or unwritable frame destination still fails when delivery uses
the owned-backing copy helpers. Alternate-stack state follows the actual saved
or restored RSP, including an edited context. A nested handler already executing
there allocates below its current RSP. Query/change checks use the calling
syscall's actual user RSP; changing an active alternate stack returns `EPERM`.

Durable frame records are heap-owned and linked to the receiving thread. They
retain value copies, not IST/kernel-stack pointers or another thread's user
stack. Main-stack frame preparation uses the existing new-page commit and
retirement path without waiting for TLB acknowledgements on the IST stack.
Safe pagewise copies enforce backing ownership and write permissions.

Sigreturn requires the exact current thread's top active frame, address, owner
TID and sequence. It validates ABI fields, user RIP/RSP, fixed user selectors,
permitted RFLAGS and MXCSR against the CPU's own mask before restoring FP state.
A rejected return retains the active record. Successful return restores the
edited mask and register/FP state; thread teardown reclaims remaining records
after scheduler quiescence. The current FXSAVE64 ABI covers x87 and SSE, not
XSAVE/AVX state.

## Blocking operations and remaining scope

Futex waits and `SYSCALL_SLEEP_INTERRUPTIBLE` can return `-EINTR` for a pending
unblocked signal. Libc mutex, once and pthread publication waits retry. Timed
condition waits preserve their relative deadline and reacquire the mutex.
`nanosleep` receives the remaining duration captured before the handler runs,
with timer rounding clamped to the original request. Legacy sleep syscall 36
is unchanged.

Caught delivery is deferred while a thread has a registered I/O request. The
existing request-cancellation operation abandons a terminating caller; using it
for catchable signals could discard consumed bytes. General I/O interruption
still needs backend acknowledgement and completion/partial-result precedence.
`SA_RESTART` is accepted for handler setup but does not supply that missing I/O
restart mechanism. Handler code must not treat ordinary pthread/libc locks as
async-signal-safe.

`sigsetjmp`/`siglongjmp` now use syscall 67 to capture a native checkpoint and
unwind newer owned signal frames before returning directly to its continuation.
Optional signal-mask restoration, current FP state, negative/zero return values,
ancestor targets and stale/foreign checkpoint rejection passed the eight-CPU
`signal-jump-qemu.log` fixture: 64 hardware-fault jumps and 512 repeated jumps.
Plain `longjmp` does not perform this signal-frame cleanup. General C activation
lifetime violations remain undefined behavior; the kernel cannot detect all of
them. See `ports/zen/signal_jump/ABI_PLAN.md` for the native 128-byte ABI.

Process groups, job-control stop/continue, real-time queued signals,
timed signal waiting, `sigsuspend` and XSAVE/AVX contexts remain unimplemented.

## Validation

The full integrated build and active production host tests passed.
`tests/signal_contract_test.py` runs 201 plain and ASan/UBSan assertions against
the production module, plus mapping/guard/heap classification checks. It covers
one-shot selection interleavings, edited-RSP/stale-stack state, masks, nested
frames, forged returns, FP validation, allocation/copy failure, I/O deferral,
interrupted sleep, synchronous wait publication/cancellation, failed output
preservation and cleanup. Futex, pthread and libc++ threading contracts
also pass. Guest-evidence parser tests reject wrong process/status/vector/site
and a real ELF copy whose expected UD2 is replaced with NOP.

The native normal fixture passed with this marker in
`build/test-out/signal-kernel-normal-qemu.log`:

```text
SIGNAL_KERNEL_TEST: PASS workers=8 cpu_mask=0xFF signals=96 gpr=15 xmm=16 x87=1 alt=1 nested=1 forged=1 redzone=1 async=1 masks=1 sleep=1 stack=1 edited_rsp=1
```

It covers concurrent #PF/UD2 delivery, nested alternate stacks, edited PC/RSP,
rejected frame/MXCSR/selector/owner forgeries, migration during a handler,
all GPRs/16 XMM registers/x87/flags, fresh main-stack commitment, discarded
read-only versus unmapped faults, asynchronous red-zone preservation, masks and
interrupted sleep.

The default and unusable-frame guests also passed. Their logs are
`build/test-out/signal-kernel-default-qemu.log` and
`build/test-out/signal-kernel-badframe-qemu.log`. The default case matches the
armed PID/TID to kernel SIGTERM/status 143/source `raise`. The unusable alternate
stack case matches SIGILL/status 132/source `fault`, vector 6 and the exact
`signal_badframe_probe` UD2 in the ELF, followed by the authoritative user-fault
record and a successful `fault_recovered` shell command.

Reproduce the active implementation checks after a normal `make`:

```sh
python3 tests/signal_contract_test.py
python3 tests/futex_contract_test.py
python3 tests/pthread_contract_test.py
python3 tests/libcxx_threading_contract_test.py
python3 ports/zen/signals/build_fixture.py --active
python3 ports/zen/signals/guest_test.py --mode all --timeout 120
```

`tests/signal_test.c` is the separate 2,048-raise/persistent-handler/abort
regression, run by `tests/signal_qemu_test.py`. All four modes also passed against
this active kernel implementation: dispatch, default FPE, returning abort handler
and ignored abort. Their logs are `build/test-out/signal-dispatch-qemu.log`,
`signal-default-fpe-qemu.log`, `signal-abort-handler-qemu.log` and
`signal-abort-ignored-qemu.log` in the same directory. Each requires its marker
and shell return; the default FPE log also records kernel signal 8/status 136.
