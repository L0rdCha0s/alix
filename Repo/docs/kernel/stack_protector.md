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
linker script runs the uninstrumented ELF TLS-fixup bootstrap, then guard
initialization, ahead of all ordinary preinit entries and C/C++ constructors.
Startup has already cleared BSS and installed ELF TLS.
Both `crt0` and the guard implementation are compiled without stack protection,
so initialization does not change the guard underneath an existing protected
frame.

Initialization fills the guard through the real `getentropy` implementation.
It retries an all-zero result at most eight times and accepts only a nonzero
result. An entropy error or exhausted zero retries terminates the process with
status 127 and the single serial line `ALIX_STACK_PROTECTOR: entropy unavailable`.
There is no predictable fallback guard. The initialized guard remains constant
for the process lifetime and all threads use it. The guard and failure handler
have default ELF visibility so protected shared objects use the same process-wide
symbols. The upstream executable driver retains the SSP archive through
`-Wl,-u,__stack_chk_guard`, including for otherwise uninstrumented programs,
so protected DSOs always find the initialized canonical runtime. Ordinary
Make-built programs retain the optional archive when instrumentation needs it.
The loader rejects a missing strong guard import.

A detected mismatch writes `ALIX_STACK_PROTECTOR: stack corruption` and invokes
the raw process-exit syscall with status 127. It does not enter heap allocation,
stdio locking, TLS destructors or process exit callbacks from the damaged frame.

`tests/stack_protector_contract_test.py` executes production initialization and
failure code with host syscall models, covering every retry boundary and error.
`make zen-ssp-test` uses real Alix Clang instrumentation, verifies the linker's
runtime preinit order, and proves an uninstrumented object gains no canary
checks while its upstream executable exports the canonical SSP runtime.
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
after an expected fatal guard failure.

`make zen-ssp-loader-qemu-test` loads an actual protected DSO from an exported
native executable. It checks the canonical guard, a protected constructor,
512 calls on eight CPUs and native environment snapshot/free imports under
Mozilla's hidden-visibility compilation mode. A second guest deliberately
overflows a protected plugin frame and verifies process wait status `127 << 8`
alongside the real stack-corruption marker. The logs are
`ssp-loader-qemu.log` and `ssp-loader-corrupt-qemu.log` in `build/test-out`.
