# Signal-aware nonlocal jumps — pending ABI 67

The active 64-byte `jmp_buf` and its integer-register setjmp/longjmp remain
unchanged. A distinct 128-byte `sigjmp_buf` starts with that same register prefix
(RBX/RBP/R12–R15/RSP/RIP), then carries version/size, owner TID, kernel-assigned
thread-lifetime epoch, target active-signal-frame sequence, optional saved mask,
flags/reserved word and two reserved u64 words.

Syscall 67 `SIGNAL_JUMP` takes operation (CAPTURE=0, RESTORE=1), buffer pointer,
128-byte capacity, and save-mask boolean or signed int return value. CAPTURE
copies the already saved 64-byte register prefix and writes native metadata.
The naked entry saves the actual caller's continuation; it does not return
through a C helper whose activation has expired. RESTORE validates the complete
snapshot before changing any kernel frame, then drops only newer records,
retains an active ancestor target, restores the mask only when requested, and
rewrites the syscall return directly to the saved user continuation. Pending
signals observe that continuation after commit. Zero jump value becomes one.

Epochs are kernel-owned, stable for the thread lifetime and issued from a
nonwrapping monotonic allocator. Nonzero target sequences must still be present
in the current thread's active chain. This rejects cross-thread buffers and
checkpoints inside retired signal handlers while allowing repeated jumps to a
still-live checkpoint. The ordinary C activation lifetime of a function which
has returned cannot be detected generally without compiler instrumentation;
such jumps remain undefined behavior. The checkpoint is caller-owned context,
not an authenticated capability for another thread.

No per-checkpoint persistent kernel allocation or user pointer is retained.
The kernel uses a temporary value snapshot and frees it before returning. Failed
copy, allocation, owner/epoch, reserved fields, PC/SP or target checks preserve
the active chain and mask. Public siglongjmp is noreturn; invalid checkpoints
terminate through raw exit 127 instead of reporting successful continuation.
The raw syscall returns negative errors for acceptance tests.

Unwinding does not restore FXSAVE images from discarded signal handlers: the
current floating-point environment is retained. WG14 N1570 §7.13.2.1p3 and
footnote 249 explicitly preserve abstract-machine state, including FP status,
as of longjmp (https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf,
printed page 263). Optional mask semantics are documented by IBM's native
siglongjmp interface (https://www.ibm.com/docs/en/i/7.5.0?topic=s-perform-nonlocal-goto-signal-handling-siglongjmp).
Normal sigreturn continues to restore its saved/edited FP context.

Pinned Gecko `mozglue/misc/MmapFaultHandler` uses `sigsetjmp(...,0)` and a
`SA_SIGINFO|SA_NODEFER|SA_ONSTACK` handler which calls siglongjmp. This is a real
build requirement; exposing a typedef or aliasing plain longjmp cannot satisfy
kernel-frame cleanup.
