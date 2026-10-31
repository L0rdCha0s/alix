# Native signal-aware jumps

`signal-jump.pending.patch` adds real `sigsetjmp`/`siglongjmp` over native syscall
67. The eleven-file artifact was applied on 2026-10-31, with every output hash
verified against the reviewed stage. Native eight-CPU acceptance passed.
`pending.json` retains the integration hashes. Do not regenerate or reapply
the pre-integration artifact against the active tree.

The existing 64-byte `jmp_buf` and plain setjmp/longjmp ABI are preserved.
`sigjmp_buf` is a distinct 128-byte native structure. Its first 64 bytes save
RBX/RBP/R12–R15/RSP/RIP; the remainder contains version/size, owner TID, a stable
kernel-issued thread epoch, target active-frame sequence, optional saved mask,
flags and reserved words. [ABI_PLAN.md](ABI_PLAN.md) records the wire and source
semantics in detail.

CAPTURE writes owner/epoch/frame/mask metadata only after checking the saved
continuation against the naked entry's actual caller return slot. RESTORE
validates the complete snapshot before changing any active record, pops only
newer frames, restores the mask iff requested, recomputes alternate-stack status
from RSP, and changes the syscall return directly to the saved continuation.
Zero becomes one; all signed nonzero int values remain intact. Pending signals
are delivered relative to that continuation, with no intermediate user helper
activation. Current x87/SSE state is retained; old handler FXSAVE images are
not restored during a nonlocal jump.

There is no persistent per-checkpoint allocation or saved pointer to the user's
checkpoint buffer. A stable per-thread epoch comes from a nonwrapping monotonic
allocator. Foreign-thread and retired-handler checkpoints reject; repeated
jumps to a still-active checkpoint remain valid. This does not claim to detect
an arbitrary returned C activation or all scope/lifetime violations. Plain
legacy longjmp is not an alias for signal-aware unwind; use the matching
sigsetjmp/siglongjmp pair when leaving a native signal handler. Invalid public
checkpoint use terminates through raw exit 127; raw syscall errors remain
observable for tests.

## Completed checks

- All changed production C units compile for native x86-64 Alix with warnings
  treated as errors. Both GCC and the actual Alix Clang driver compile the naked
  user entry, and objdump confirms caller RIP/RSP are saved before int80 with no
  intervening C call.
- Combined production signal/checkpoint host contracts pass plain and ASan/UBSan:
  285 assertions. They cover existing signal behavior plus zero/negative values,
  mask save/no-save, pending delivery at the restored continuation, ancestor/all
  frame unwinding, repeated checkpoints, current FP retention, invalid fields,
  foreign ownership, retired frame sequences, failed copies/allocation, active
  I/O refusal, and epoch exhaustion without reuse.
- The native acceptance ELF links with the active runtime and no undefined
  symbols: `out/signal_jump_test.elf`. It passed inside Alix, covering
  eight pinned CPUs, 64 real UD2 handler jumps, 512 repeated zero-to-one jumps,
  -7/-1/INT_MIN returns, saved/unsaved masks, pending delivery, nested all-frame
  and ancestor-only unwind, current x87/MXCSR flags and rounding, stable/distinct
  thread epochs, foreign and retired checkpoint rejection, inaccessible input,
  fresh captures proving empty post-unwind chains, and a plain jmp_buf regression.

The native log is `build/test-out/signal-jump-qemu.log`; the completed harness
reported PASS after normal shell recovery. This proves the signal-aware jump
facility, not execution of the browser.

## Integration record

The completed pre-application checks were:

```sh
python3 ports/zen/signal_jump/check_pending.py
python3 ports/zen/signal_jump/host_contract_test.py
python3 ports/zen/signal_jump/build_fixture.py
```

After root review, apply from the parent Git root:

```sh
git apply --check Repo/ports/zen/signal_jump/signal-jump.pending.patch
git apply Repo/ports/zen/signal_jump/signal-jump.pending.patch
```

Rebase before applying if the independently prepared READLINK 66 or uptime 68
batches have changed shared syscall files. Then run the normal full `make`, the
existing signal contracts, and the native acceptance using rebuilt active objects:

```sh
python3 tests/signal_contract_test.py
python3 ports/zen/signal_jump/host_contract_test.py --active
python3 ports/zen/signal_jump/build_fixture.py --active
python3 ports/zen/signal_jump/guest_test.py --timeout 120
```

The guest driver refuses a kernel without `process_signal_jump`, uses the
established disposable `run-via-agent.sh` harness, and writes
`build/test-out/signal-jump-qemu.log`. Native acceptance is required before
claiming this engine integration gate is complete. Ordinary signal, pthread,
C++ and Rust regressions should use the rebuilt runtime afterward.
