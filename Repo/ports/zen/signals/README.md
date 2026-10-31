# Native signal delivery

The reviewed implementation was applied to the active kernel/runtime on
2026-10-31. Normal, default-termination and corrupted-return guest modes all
passed in native eight-CPU Alix guests. Zen and the SpiderMonkey executable
have not been run by this task.

`signals.pending.patch` contains 26 files, including the kernel/user ABI,
production signal module, syscall integration, user wrappers, preemption stub,
wait handling, and affected host-test models. `pending.json` records the exact
active input and staged output hashes; all 26 applied outputs matched those
hashes. The rebase scripts preserved the active idle reaper, I/O service/factory
and boot diagnostics. `pending/` retains the reviewed sources. Do not run either
rebase script or the old-baseline provenance check after application.

## Behavior implemented in the pending sources

- Native `sigaction`, `siginfo_t`, named-register `ucontext_t`, `sigaltstack`,
  `sigprocmask`, `sigpending`, mask helpers, `signal`, `raise`, `kill`,
  `pthread_sigmask`, and `pthread_kill` share one kernel registry. Dispositions
  belong to the process; masks, alternate stacks, pending signals and active
  frame records belong to threads. New threads inherit the creator's mask.
- Syscalls 59–64 are SIGACTION, SIGPROCMASK, SIGALTSTACK, SIGRETURN, RAISE and KILL;
  syscall 65 is SLEEP_INTERRUPTIBLE. Existing syscall 36 is unchanged.
- Demand-zero and main-stack recovery run before SIGSEGV. Unrecoverable user
  #PF/#UD/#DE/#GP/#SS faults can enter handlers. Mapping metadata distinguishes
  MAPERR from ACCERR even when MADV_DONTNEED left the PTE nonpresent.
- Full GPR/RIP/RSP/RFLAGS and FXSAVE64 state enter a native editable context.
  Handler entry clears DF and has the SysV stack alignment. Return validates
  the exact current-thread active frame, sequence, selectors, user addresses,
  safe flags and the CPU's MXCSR mask. Invalid returns preserve the active
  chain; teardown reclaims all remaining heap records after thread quiescence.
- Signal frame preparation may commit fresh main-stack pages through the
  existing new-page/retirement path. It does not wait for TLB acknowledgements
  on an IST stack. Other destinations use the owned-backing copy routines.
- The RX restorer occupies offset **0x200** of the first existing stub page;
  offset 0x100 remains the thread-exit stub. The user preemption stub protects
  the 128-byte red zone, is 73 bytes long, returns from int80 at +38, and uses
  `ret 128`. Signal delivery reconstructs the actual interrupted instruction
  and original register order from the 264-byte saved area.
- Pending caught signals deliver at syscall return or timer-preempt SYS_YIELD.
  Futex and new sleep waits wake with EINTR. Libc mutex/once/publication waits
  retry; timed conditions preserve their deadline. `nanosleep` reports the
  pre-handler remaining duration, clamped to the original request.
- Running/queued I/O requests are **not abandoned** for caught signals. Delivery
  waits until registered I/O completes and its result has been consumed.

## Evidence completed before review

- All 13 staged production C translation units compile for x86_64 Alix with
  `-Wall -Wextra -Werror`; kernel units use general-register-only code generation.
- Production kernel signal host contracts pass plain and ASan/UBSan: 172
  assertions cover nested frames, masks, ignored/default dispositions, active
  ownership, invalid returns, FP policy, preemption register reconstruction,
  allocation/copy failures, I/O deferral, interrupted sleep and cleanup.
  One-shot selection is atomic; regression interleavings verify a subsequent
  registration survives frame publication. Edited-RSP and stale-status cases
  verify alternate-stack ownership follows the actual instruction stack.
  Privileged kernel boundaries and the host-incompatible FXSAVE instruction are
  modeled; these results do not establish native instruction delivery.
- A separate production-helper sanitizer test checks logical VM reservation,
  discarded mapping, image, heap-brk, and main-stack/guard classification.
- Updated existing futex/condition/mutex host tests pass, including EINTR before
  and after waiter publication and condition deadline preservation. Existing
  pthread production tests pass with the staged header/runtime.
- Target-object byte checks verify the exact user preemption/restorer contracts.
- Guest-evidence parser contracts pass 32 cases, including wrong PID/TID, status,
  signal, source, vector and instruction rejection. The actual ELF symbol must
  contain UD2; a copy with that opcode replaced by NOP is rejected.
- The real target ELF `out/signal_kernel_test.elf` was rebuilt with the applied
  native libc, has no undefined symbols and passed all three guest modes.
  Normal acceptance covered 96 signals across eight CPUs, all 15 GPRs and
  16 XMM registers, x87, nested alternate stacks, edited RSP, frame forgeries,
  asynchronous red-zone preservation, masks and interrupted sleep. Negative
  modes matched exact kernel termination records and recovered the shell.

The native fixture includes eight concurrent alternate-stack handlers, #PF and
UD2, nested delivery, context PC edits, frame/MXCSR/selector/owner forgeries,
thread migration during a handler, all 15 GPRs/16 XMM registers/x87/flags, fresh
main-stack frame commitment, discarded read-only and unmapped fault distinctions,
red-zone-sensitive asynchronous loops, coalesced blocked signals and nanosleep
interruption. A separate context edit moves RSP into the middle of the
alternate stack, exercises nested delivery below live stack frames, then returns
to the original stack. `default` and `badframe` modes require process termination and
shell recovery. They match a one-line kernel signal record to the armed PID/TID,
source and exit status; badframe also requires vector 6 and the original ELF UD2
instruction in the authoritative user-fault record. `tests/signal_test.c` remains the additional 2048-raise and abort
regression and should be run again after integration.

## Review and integration

The following commands describe the completed pre-application review; the
old-baseline provenance check is not valid against the already-applied tree:

```sh
python3 ports/zen/signals/check_pending.py
python3 ports/zen/signals/build_fixture.py
python3 ports/zen/signals/host_contract_test.py
python3 ports/zen/signals/mapping_contract_test.py
python3 ports/zen/signals/stub_contract_test.py
python3 ports/zen/signals/harness_contract_test.py
PYTHONPATH=tests python3 ports/zen/signals/pending/tests/futex_contract_test.py
```

The reviewed patch was applied from the Git root (the parent of `Repo`):

```sh
git apply --check Repo/ports/zen/signals/signals.pending.patch
git apply Repo/ports/zen/signals/signals.pending.patch
```

For subsequent validation, run the normal full `make`, affected host checks, existing native exception,
preemption, TLS/C++/Rust/pthread regressions, and the native signal tests:

```sh
python3 tests/signal_contract_test.py
python3 tests/futex_contract_test.py
python3 tests/pthread_contract_test.py
python3 ports/zen/signals/build_fixture.py --active
python3 ports/zen/signals/guest_test.py --mode normal --timeout 120
python3 ports/zen/signals/guest_test.py --mode default --timeout 60
python3 ports/zen/signals/guest_test.py --mode badframe --timeout 60
```

The guest runner uses the established `run-via-agent.sh` disposable eight-CPU
QEMU harness and checks that the built kernel contains signal support before
booting. It does not write the user's persistent disk. Native logs are
`build/test-out/signal-kernel-{normal,default,badframe}-qemu.log`.

## Remaining scope

Native execution and ownership review have passed. The explicit Gecko
bridge must include `sys/ucontext.h` and map its PC/BP/SP macros to native
`uc_mcontext.rip/rbp/rsp` (64-bit named lvalues). No Linux context structure or
Wasm/JIT disabling is needed.

This does not implement process groups, job-control stop/continue, real-time
queued signals, sigwait/sigsuspend, signal-safe nonlocal unwinding/siglongjmp,
or XSAVE/AVX contexts. Group/job-control forms return ENOTSUP; unknown action
flags return EINVAL. Unmasked synchronous faults with ignored/blocked/unusable
handlers use default termination. Nonlocal escape from a handler can leave its
active records until teardown and is not supported. SA_RESTART is accepted for
common handler setup; there is no general interrupted-I/O restart implementation.
Catchable signal interruption of in-flight I/O requires a separate backend
acknowledgement/partial-result protocol and remains necessary port work.
