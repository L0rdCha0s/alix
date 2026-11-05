# Unaligned copy performance, 5 November 2026

This continues the [scheduler and guard-configuration pass](performance-pass5-2026-11-05.md).
Kernel stack-debug guards remain disabled at the user's request. This pass changes
user libc copy routines and expands the existing performance app; it adds no
separate test harness.

## Find the alignment penalty

The old user memcpy used word copies only when source and destination had the
same alignment. Other copies fell through to eight individual byte assignments.
Backward memmove similarly used a byte loop when its pointers had different
alignment. Forward memmove delegated to memcpy. Disassembly confirmed these
fallbacks were still present in the executable.

The existing 64 KiB move workload shifts by 16 bytes, so its equally aligned
pointers missed this behavior. Four new default cases cover unaligned memcpy at
4 KiB/1 MiB and forward/backward one-byte shifts at 64 KiB. The default inventory
now has 79 cases. Existing workload operation definitions remain unchanged.
Copy cases verify the entire final payload after timing. Move cases count actual
calls, including warmup and calibration, and verify their final array against an
independent original-index calculation after timing. Each timed operation still
performs exactly one move.

The opt-in `memory_copy_guard_pages` diagnostic uses the same native app. It
checks 66,068 separate-buffer copies/moves and 272,452 same-buffer moves, plus
self/zero-length calls: lengths 0–257, 4095 and 4096, all 8x8 alignments where they
fit, both page edges and every overlap gap 1–33 in both directions. Guard pages
surround both usable pages; the source page is read-only. Byte oracles check
payloads, return pointers and destination canaries. Its timing includes validation
and is not a copy throughput measurement. These ordinary user VM protections are
separate from kernel stack guards.

## Remove the byte fallback

User memcpy now uses packed, aliasable 64-bit accesses at all alignments, in
bounded groups of 32 bytes, then eight-byte words and a byte tail. Forward
memmove uses the same helper. Backward moves copy groups in reverse order, loading
each word before its corresponding store so one-byte overlaps remain valid.
Every access stays within the requested range. There is no temporary shared
buffer or cross-thread stack handoff.

The kernel copy implementation already supports unaligned words and is unchanged
in this pass. Kernel memset also has compiler-generated word stores despite its
byte-loop source; source appearance alone did not justify changing it.

Two fresh CLI boots before and after use five requested 100 ms rounds per memory
case. Values below are ranges of per-boot p50 batch-average microseconds per
operation, not confidence intervals:

| Workload | CLI before | CLI after | GUI before | GUI after |
| --- | ---: | ---: | ---: | ---: |
| Aligned memcpy 4 KiB | 3.051–3.356 | 3.051 | 3.051 | 3.356 |
| Aligned memcpy 1 MiB | 156.250 | 146.484–156.250 | 156.250 | 156.250 |
| Unaligned memcpy 4 KiB | 6.256–6.561 | 3.509 | 6.561 | 3.356 |
| Unaligned memcpy 1 MiB | 185.546–195.312 | 156.250 | 175.781 | 166.015 |
| Backward memmove, 16-byte gap, 64 KiB | 9.765–13.427 | 10.986–11.596 | 9.765 | 10.986 |
| Backward memmove, one-byte gap, 64 KiB | 126.953 | 11.596–12.207 | 126.953 | 12.207 |
| Forward memmove, one-byte gap, 64 KiB | 83.007 | 9.765–11.596 | 83.007 | 9.765 |

The one-byte moves improve about 10–11x backward and 7–8.5x forward in CLI.
Their observed sample ranges, expanded by the advertised tick per operation,
remain separate in both CLI comparisons and the GUI comparison. Unaligned memcpy
also improves, but its descriptive ranges overlap; avoid assigning it the same
strength of timing evidence. The 16-byte move and aligned copy controls do not
show a consistent improvement. Unchanged allocator/compare cases vary between
runs and are not claimed as benefits of this patch.

The focused GUI memory run retains a 20 ms p95 frame interval, with maximum
30 ms after versus 50 ms before, and zero dropped events or GUI errors. Maxima
from one run are not proof of a UI latency improvement. Measurements use the
standard 10 ms clock and eight-CPU QEMU environment; they do not establish
physical-machine or scanout latency.

## Build and evidence

A clean build exposed macOS's fortified snprintf macro expanding inside the
Alix declaration. Parenthesizing the function name in `include/libc.h` prevents
that expansion while preserving fortified calls. This header fix precedes all
recorded memory baselines.

Fresh evidence is under `build/perf/pass6-20261105`: `memory-before{,-2}`,
`memory-after{,-2}`, `memory-gui-{before,after}` and `copy-guard-{before,after}`.
Each report retains raw batches, host conditions, kernel/app/loader fingerprints
and evaluator fingerprints. Comparisons are `memory-comparison{,-2}.txt` and
`memory-gui-comparison.txt`; source snapshots, `pass6.patch` and final assembly
are adjacent. All these runs have unchanged build/evaluator inputs during
measurement. The kernel image is identical across this pass; the loader relink
changes its PE fingerprint and GUI terminals are relinked with the updated libc.

The previous build directory was replaced between inspections during this pass.
Earlier pass reports remain historical records; their raw build evidence is no
longer present. The measurements above come from newly recorded baselines.
No persistent data image is changed by these disposable guest runs.

## Validation

- Guarded copy diagnostic passed before and after the change. All six focused
  memory runs completed their 20 cases with no failures.
- Fresh CLI and GUI runs each completed all 79 default cases with zero failures.
  CLI skipped optional DNS; GUI skipped DNS and multithreaded fork. The full GUI
  run retained 1,000 load frame intervals: p95 20 ms, maximum 40 ms, zero dropped
  events and no GUI error.
- Existing native libc legacy/owned-descriptor and quick-exit checks passed.
  Anonymous VM/JIT, protected user-copy races, and hardware write/none/execute
  fault checks passed. These are behavioral fixtures, not a claim of full POSIX
  or C standard conformance.
- Existing native compositor checks passed: exact framebuffer pixels, 128
  presents, repeated resize/control ownership and raw keyboard input on eight
  CPUs. The captured PNG was inspected. This is native Alix GUI evidence; it
  does not validate a Gecko/Zen browser.
- `effective-stack-flags.txt` records all eight requested kernel debug switches
  at zero. Disassembly confirms `thread_stack_guard_intact` returns true
  immediately, and the compiled scheduler stack-protection mode is zero.
- Default `make`, the existing fixture builds, Python parsing and whitespace
  checks pass. The known trampoline GNU-stack linker warning remains.

`verified-runs.json` records the current reports and hashes. Existing native
serial logs, boot receipts and compositor capture are retained in
`native-check-evidence/`. No kernel guard or permission-cache prototype has been
re-enabled.
