# Native Alix signal ABI and implementation phases (pending)

No active kernel or runtime file is changed by this proposal. Syscalls 59–64
are currently free after `TIMEZONE_INFO=58` and are reserved here for SIGACTION,
SIGPROCMASK, SIGALTSTACK, SIGRETURN, RAISE and KILL respectively. Syscall 65 is
reserved for SLEEP_INTERRUPTIBLE; existing sleep syscall 36 is preserved.

## Upstream requirements

Pinned `js/src/wasm/WasmSignalHandlers.cpp` installs the x64 `SIGSEGV` and
`SIGILL` handlers using `SA_SIGINFO | SA_NODEFER | SA_ONSTACK` (lines 908–935).
It reads `siginfo_t.si_addr` for memory traps and reads/edits the saved PC through
the context macros. Unhandled traps restore or chain the previous disposition;
returning then re-executes the faulting instruction. The Alix bridge must expose
its own named-register context, not pretend to have Linux `gregs[]` structures.

Existing demand-zero, heap and main-stack recovery remains first for page faults.
A handled allocation fault must not become a user signal. Unrecoverable user
faults enter signal selection; kernel faults keep the existing kernel-failure
path. A synchronous fault that is blocked or ignored cannot be postponed while
re-executing the same instruction indefinitely; the proposed Alix policy is
default termination in that case.

## Proposed wire structures

All widths and offsets will have C/static-ELF tests. This is native x86-64 ABI
version 1, with 64-bit pointers and FXSAVE64 state; it does not claim XSAVE/AVX
context support.

- `sigset_t`: one 64-bit mask; signal n uses bit n−1. Basic helpers validate
  supported signal numbers. Uncatchable signals cannot be blocked/ignored.
- Action wire: handler address u64, mask u64, flags u32 and reserved u32 (24 bytes).
  Public `struct sigaction` has the standard handler/sigaction union and matching
  mask/flags; the kernel never calls the user pointer directly.
- `stack_t`: pointer, size, flags and reserved word (24 bytes).
- `siginfo_t`: signo/errno/code/status, fault address, PID/UID/TID, hardware
  vector/error and reserved space (64 bytes).
- `mcontext_t`: r15..rax in the existing exception/syscall GPR order, then
  RIP/CS/RFLAGS/RSP/SS, trap number/error/CR2 and a reserved word. A 16-byte-aligned
  512-byte FXSAVE area starts at offset 192; total size 704 bytes.
- `ucontext_t`: version/size, flags/link, mask, alternate-stack snapshot and
  reserved padding, followed by `uc_mcontext` at offset 64; total size 768 bytes.
- Private user-frame header: magic/version/size, owner TID, sequence and exact
  frame address, followed by siginfo/ucontext. Kernel ownership and the active
  chain are heap records, not user pointers or pointers into IST/kernel stacks.

The handler receives `(signo, &info, &context)` in RDI/RSI/RDX. Its RSP is 8
modulo 16, with an RX restorer return address in the existing first stub page
at offset `0x200` (`0x100` already contains the thread-exit stub). The interrupted 128-byte red zone is left untouched. Alternate
stacks are explicitly registered writable user ranges; nested handlers already
on that stack allocate below their current RSP. Main-stack frame construction
can reuse the existing no-wait growth helper, then copy through owned backing.

The sigreturn caller must match the current thread's top active record, exact
user frame address and sequence. Copy the editable user context into heap-owned
kernel storage, validate it fully, then pop the record and restore state. Return
RIP/RSP must be canonical and within the native user window. CS/SS are fixed to
Alix's user selectors; privileged/reserved RFLAGS are rejected and handler entry
clears DF. Validate MXCSR against a kernel-owned CPU mask before FXRSTOR; do not
trust the mask in the supplied image. A failed return leaves the active record
and hardware FP state intact. Kernel code after FP restoration must remain
general-register-only until IRET.

## Phases and acceptance

1. **Synchronous native delivery.** Process-owned dispositions; thread-owned
   mask/altstack/active records; real fault and self-raise delivery; a common
   kernel registry for `signal`, `sigaction`, `raise` and abort. Tests cover
   demand-zero-before-handler, #PF/UD2 handlers, editable PC, alternate-stack
   nesting, mask restoration, full registers/flags/FP, and invalid sigreturn.
2. **Queued asynchronous delivery.** Process and thread posts, ownership/lifetime
   checks, delivery at full syscall return frames and timer-preempt SYS_YIELD.
   Signals pending while masked remain queued. Delivery restores actual
   interrupted state, including the preemption-stub reconstruction below.
3. **Interrupted blocking operations.** Wake futex/sleep waits with a distinct
   EINTR result, preserving deadlines; libc mutex/once/condition code must retry
   or reacquire correctly. I/O must either cancel before consuming data or return
   completed/partial results before delivering a signal. Detaching an in-flight
   read and discarding consumed bytes is not acceptable. Deferred delivery during
   uncancellable I/O is a limitation, not complete POSIX interruption support.

Each phase needs native acceptance, not just compiling declarations or host
models. Do not describe asynchronous support as complete while blocking/I/O
semantics remain unresolved. Process groups, job-control stop/continue, real-time
queued signals and any unimplemented flags must fail explicitly until provided.

## Preemption stub correction

The current stub pushes 136 bytes immediately below interrupted RSP and thereby
overwrites the red zone. The pending correction prepends flag-preserving
`lea rsp,[rsp-128]`, retaining the saved-register offsets, and ends with
`ret 128`. Total RSP displacement becomes 264 bytes; the saved flags remain at
offset 0, the legacy user-stub GPR order at offsets 8..120, and the resume slot at 128. SYS_YIELD returns
at stub+38 instead of stub+33.

For asynchronous delivery from this return site, copy the saved registers from
user memory into the kernel-owned record, use the kernel's recorded resume RIP
and reconstruct original RSP as stub_rsp+264. The user stub has rdi/rsi and
rbx/rdx/rcx in a different order from exception_entry, so reconstruction maps
those fields explicitly. Redirect directly to the handler;
after sigreturn execution resumes at the original instruction. Ordinary yields
and other syscalls use their normal full syscall frame. Dedicated tests must
exercise red-zone bytes, all GPRs, FP and migration across eight CPUs.

## Ownership and integration

Dispositions live with the process. Pending masks, altstack state and active
records live with the thread; new user threads inherit the creator's blocked
mask, but not its active frames or alternate stack. All persistent records are
heap-owned and reclaimed only after existing scheduler quiescence checks.
Keep kernel services outside user kill targets. Scheduler/thread-list locking
must precede subsidiary memory/queue operations; do not wait for TLB completion
or retain locks across user execution, IST return, or handler invocation.

`pthread_sigmask` and `pthread_kill` must use the same registry and native TID
ownership. RAISE can carry an optional same-process target TID; KILL targets a
positive user PID with normal ownership checks. Process-group forms require
actual process-group support and cannot be silently treated as a single PID.

Signal-safe nonlocal jumps and handler-frame unwinding are additional work;
active records are reclaimed on normal sigreturn or final thread teardown.
See README.md for current compile/host evidence and the unexecuted native fixture.
