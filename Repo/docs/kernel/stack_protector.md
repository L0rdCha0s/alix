# Native user stack protection

The Alix Clang target emits references to a process-wide `__stack_chk_guard`
and calls `__stack_chk_fail` when a protected frame's saved value differs. The
actual object-code probe is checked with `x86_64-elf-objdump`; this ABI does not
use another OS's `FS:0x28` thread-control-block field.

`user/lib/stack_protector.c` supplies these symbols in the optional
`build/user/lib/libalix-ssp.a` archive. It is not part of `USER_COMMON_OBJECTS`.
The native upstream compiler driver includes the archive in its link group, so
an executable acquires it only when an instrumented object references its
symbols. Existing unprotected applications retain their previous entropy
requirements.

The archive also contributes a `.preinit_array.alix_runtime` entry. The user
linker script places that entry first, ahead of all ordinary preinit entries
and C/C++ constructors. Startup has already cleared BSS and installed ELF TLS.
Both `crt0` and the guard implementation are compiled without stack protection,
so initialization does not change the guard underneath an existing protected
frame.

Initialization fills the guard through the real `getentropy` implementation.
It retries an all-zero result at most eight times and accepts only a nonzero
result. An entropy error or exhausted zero retries terminates the process with
status 127 and the single serial line `ALIX_STACK_PROTECTOR: entropy unavailable`.
There is no predictable fallback guard. The initialized guard remains constant
for the process lifetime and all threads use it.

A detected mismatch writes `ALIX_STACK_PROTECTOR: stack corruption` and invokes
the raw process-exit syscall with status 127. It does not enter heap allocation,
stdio locking, TLS destructors or process exit callbacks from the damaged frame.

`tests/stack_protector_contract_test.py` executes production initialization and
failure code with host syscall models, covering every retry boundary and error.
`make zen-ssp-test` uses real Alix Clang instrumentation, verifies the linker's
first preinit pointer, and proves an unprotected ELF does not pull in the guard.
It produces `build/user/stack_protector_test.elf` and
`build/user/stack_protector_unprotected_test.elf` for native execution. The
protected fixture checks ordinary preinit and constructor calls, plus a
`corrupt` mode which changes the guard after entering an instrumented function
and must fail through that function's real compiler-generated epilogue.
On a CPU configuration with neither RDRAND nor RDSEED, the protected fixture
must terminate before user preinit, while the unprotected fixture must run.
`python3 tests/stack_protector_qemu_test.py` runs all four modes through
`run-via-agent.sh` in isolated eight-CPU guests. All four completed successfully;
logs are `build/test-out/stack-protector*-qemu.log`. The harness requires shell
return, rejects unexpected kernel/user faults, and rejects success markers
after an expected fatal guard failure. The raw exit status 127 is additionally
covered by the production-code host contract; the shell currently discards
child exit status, so that numeric status is not independently read back by
the guest harness.
