# Native process uptime integration

Syscall 68 (`PROCESS_UPTIME_NS`) is integrated and verified in Alix, together
with the genuine Alix branch of Mozilla's `TimeStamp::ComputeProcessUptime`.
It is not a Linux syscall-header or
`/proc` emulation. The existing POSIX monotonic `TimeStamp::Now` remains intact.

Each process records its creation timer tick immediately after successful PID
allocation, before address-space setup or publication. The query pins the CPU
while reading the current process and clock, then retains only scalar values.
It subtracts ticks before converting to nanoseconds, avoiding overflow of an
absolute boot-time nanosecond counter. Conversion saturates at UINT64_MAX;
zero elapsed ticks are a valid zero result. The timer frequency is fixed at
boot; the current 100Hz timer has 10ms resolution even though this API
expresses the duration in nanoseconds. Sleeping and time spent off-CPU count
towards process uptime. Every thread observes the same process creation epoch.

```sh
python3 tests/process_uptime_contract_test.py
HOST_CC='clang -fsanitize=address,undefined -fno-omit-frame-pointer' \
  python3 tests/process_uptime_contract_test.py
python3 ports/zen/uptime/build_fixture.py
```

The original integration patch and before/after hash manifest are retained under
`build/ports/zen/process-uptime`; all nine active after hashes were checked at
integration. `prepare_pending.py`/`compile_pending.py` were used before activation
and deliberately refuse to overwrite an already integrated module. For a future
staged rebase after concurrent constructor/syscall changes, review the
small patch from the actual parent git root and verify its manifest, rather than
copying old full-file snapshots over newer work. From the `Repo` directory use:

```sh
git -C .. apply --check --directory=Repo Repo/build/ports/zen/process-uptime/process-uptime.patch
git -C .. apply --directory=Repo Repo/build/ports/zen/process-uptime/process-uptime.patch
```

Verify every active file against the manifest's `after` hash after applying.
Running plain `git apply` from this subdirectory can skip paths while returning
zero, so its status alone is not integration proof. The constructor hunk is independent of
the separately staged process-owned cwd initialization.

Host tests execute the production query and conversion code: fractional and
extreme frequency conversions, overflow saturation, young processes after huge
boot uptimes, process release at unpin, and 80,000 samples across eight threads.
The existing production PID allocation test includes a creation-timestamp
assertion. The actual constructor, dispatcher, kernel query and user wrapper
passed native compilation, followed by the coordinated full Alix build.

The native guest passed all 1,024 samples across eight CPUs, elapsed sleep-time
checks, and the common process creation epoch. Evidence is in
`build/test-out/process-uptime-qemu.log`. After later changes, rebuild and execute
`build/user/process_uptime_test.elf` in Alix and require
`PROCESS_UPTIME_TEST: PASS cpus=8 samples=1024 elapsed=1 process_shared=1` before
accepting the change. The fixture uses heap-owned thread arguments and
checks elapsed sleep time plus a common creation epoch across all CPUs.

`ports/zen/patches/0007-native-alix-process-uptime.patch` is registered in the
verified engine series and applied through `patch_engine.py`. Its before hash
was checked against the exact pinned Firefox source archive, and its result
hash is verified after application. The original staged patch and entry remain
here as provenance. The actual upstream `TimeStamp_posix.cpp` also compiles
with its configured Alix flags; its uptime dependency is
`sys_process_uptime_ns`, with no Linux syscall or `/proc` dependency.
This does not yet establish that the complete JS shell
links or runs; the real engine build must clear its remaining platform gates.
