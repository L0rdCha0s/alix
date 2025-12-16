# SSE Enablement

This document captures the current SSE policy for Alix along with the audit
trails that make userland SIMD code safe.

## Build and Toolchain

- Kernel objects continue to be compiled with `-mgeneral-regs-only -mno-sse
  -mfpmath=387`. This keeps kernel code strictly integer/x87 so no SSE
  registers are ever touched while we are running in privileged mode.
- Userland objects now use `-msse2 -mfpmath=sse -mstackrealign` (see
  `Makefile`). Every user process can freely execute SSE/SSE2 instructions.

## CPU/FPU configuration

- `src/arch/x86/kernel_entry.c` sets CR0 and CR4 bits (`OSFXSR`, `OSXMMEXCPT`,
  clears `EM`, sets `MP`, `PG`) during early boot, so the CPU accepts SSE/SSE2
  instructions from both privilege levels.
- `fpu_prepare_initial_state()` performs `fninit`/`fxsave64` once and each
  thread inherits a copy of this clean image before running.

## Context switching

- Scheduler transitions (`process.c`) always invoke `fxsave64`/`fxrstor64`
  in `fpu_save_state`/`fpu_restore_state`. User threads therefore retain their
  XMM state across yields, preemption and blocking syscalls.
- Because kernel code never executes SSE instructions (see build flags), the
  only owner of the SIMD register file is the currently scheduled thread.
  Interrupt/exception entry does not need additional save/restore work — the
  registers are untouched until the thread is either resumed or a context
  switch occurs.

## Interrupts and exceptions

- All interrupt handlers live in C (`src/arch/x86/interrupts.c`) and inherit the
  kernel compilation flags, so they stay SSE-free.
- The syscall entry path (`src/arch/x86/syscall_entry.S`) switches stacks and
  registers without touching XMM/YMM state; the callee runs with the same
  guarantees as other kernel code.

## Stack alignment

- User-mode stacks are allocated and aligned in `process_prepare_stack_with_args`
  and `process_jump_to_user`. We align the initial stack pointer down to 16 and
  respect the SysV AMD64 convention so SSE instructions that require aligned
  operands (e.g. `movaps`) are safe.
- Kernel thread stacks are also 16-byte aligned inside `thread_create`, which is
  important for any future kernel code that might opt-in to SSE via explicit
  save/restore wrappers.

## Future work

- If the kernel ever needs SSE for fast memcpy/crypto/etc., we will need
  wrappers similar to Linux’s `kernel_fpu_begin/end` that save/restore per
  thread state on demand, plus ISR glue that records whether a context switch
  occurred before attempting to restore.
- Additional exception handlers for SIMD faults (#19) can be added to deliver
  cleaner diagnostics to userland if we start unmasking MXCSR bits.
