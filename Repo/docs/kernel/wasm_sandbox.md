# Native RLBox memory and minimum WASI runtime

Gecko's real RLBox wasm2c memory and minimum WASI sources now compile and run
against Alix's native libc and VM interfaces. Managed patch `0038` selects
their existing POSIX-style mmap/mprotect implementation explicitly for Alix.
It does not enable a foreign compiler target family. Requests for addresses
below 2 GiB fail because Alix's user address arena starts above 4 GiB.

Reservations retain the upstream 8 GiB alignment and guard region. Alix's
PROT_NONE mappings reserve virtual addresses without allocating physical data
pages; mprotect commits the initial linear memory. The original alignment
algorithm trims unused prefix/suffix reservations through native partial unmap.
Destroy releases the complete remaining reservation.

WABT uses signal-aware jumps on non-Windows platforms. Alix's plain `jmp_buf`
and `sigjmp_buf` are distinct records, so patch `0039` selects the actual native
signal-aware record in WABT's wrapper. Each thread retains its own jump state;
the port preserves the runtime's existing trap and unwind mechanisms.

Minimum WASI's four clocks use native `clock_gettime` and `clock_getres`.
Process/thread CPU clocks read Alix's existing sampled scheduler counters,
excluding sleeping/off-CPU time. Resolution comes from the timer frequency,
with millisecond quantization retained for the existing wall/monotonic APIs.
`getpagesize` uses the canonical native sysconf page size.

Run `make zen-rlbox-runtime-qemu-test` for actual eight-CPU acceptance:

- Eight 8 GiB-aligned reservations, committed zero-filled pages, isolated writes
  and cleanup using the configured RLBox memory object.
- All four minimum-WASI clock imports and invalid-clock output preservation.
- Eight independent bounds traps through the actual default WABT runtime.
- Native thread CPU clocks, sleeping-main-thread exclusion and process totals.
- A separate hardware write into RLBox's reserved guard. The guest must report
  the intended user page fault at the exact address/source and recover the shell.

Serial evidence is `build/test-out/rlbox-runtime-qemu.log` and
`rlbox-guard-qemu.log`, each with a boot-image identity sidecar. The guard's
`.fault-site.txt` identifies the compiled faulting source line.
`build/ports/zen/rlbox-runtime/native-link.json` identifies the configured
memory/minWASI objects and the native ELF. The acceptance executable links
WABT's real default trap implementation; Firefox's configured production
objects instead route fatal traps through mozglue. Production `security/rlbox`
and SoundTouch sandbox compilations are separate recorded gates.

`tests/cpu_clock_contract_test.py` executes production kernel snapshots and libc
conversions under ASan/UBSan with allocation/copy failures, owner retirement,
selection, frequency/resolution, overflow and error-output checks. Existing
resource-usage conversion/concurrency contracts also pass.

This is runtime memory/import/trap evidence. It does not establish a complete
RLBox decoder sandbox, the full Gecko link or Zen startup.
