# Zen lazy file cache performance, 6 November 2026

Large files and inactive browser profiles no longer consume kernel-heap buffers
just because their volume is mounted. On the same private profile-heavy checkpoint
that previously raised signal 11 during resize, resident file capacity before
launch fell from 842,357,522 to 89,482,658 bytes. After two browser visits, allocated
kernel heap fell from 1,062,507,584 to 622,968,720 bytes: about 419 MiB less.
Free heap rose from 4,141,552 to 443,617,872 bytes, and the largest free block rose
from 1,763,456 to 436,230,080 bytes. The new run passed resize, clean browser exit
and guest-confirmed shutdown with zero allocation failures.

These are captured working-set comparisons on the same saved volume, browser
bundle, eight CPUs and 4 GiB TCG guest. Background browser work can vary, and
this is not a statistically controlled UI-latency speedup claim. The old failure
is retained in `build/perf/zen-file-cache-20261106/scheduler-final-unprofiled/`;
the new run is `build/perf/zen-lazy-cache-20261106/installed-first/`.

## Implementation and ownership

AlixFS mount retains namespace, logical size, ownership, mode and timestamps.
Regular-file payloads larger than 64 KiB start unloaded, with their validated disk
payload offset. Small files and symlinks stay eager. Reads, borrowed-buffer access
and mapping preparation materialize a file once. Metadata-only opens/stat/lookup
leave it unloaded. O_TRUNC replaces unloaded contents with a small empty buffer
without reading the bytes being discarded.

Loading owns the mount backend gate before taking the node data lock, snapshots
size/offset/data generation, then reads into owned heap storage outside the data
and namespace spinlocks. Publication rechecks the snapshot. Concurrent truncation
makes the loader discard its obsolete read. Kernel callers that can be killed
transfer a retained file into the existing registered storage-request machinery;
the protected worker owns every allocation/gate across disk waits. Service workers
and pre-service bootstrap can load directly. No caller stack or user address is
retained in a continuation. Legacy opens prepare outside FD/namespace locks;
private descriptors defer until an actual read. Mapping preparation loads before
VM publication, preserving resident-only user faults and existing COW behavior.

A rename/full writeback of an unloaded file streams its old protected extent into
a new private extent in 64 KiB chunks. Data-generation checks and publication
remain part of the existing writeback transaction. The saved payload offset is
updated after publication. Rename publishes its name/parent and dirty generation
under the same node data lock used by serialization; the retired name is freed
only after leaving that lock. This also closes a source-review finding where
writeback could copy a concurrently freed filename. Metadata-only writes do not
copy payloads. The disk
format remains version 4, with the existing version-2/3 compatibility.

This is demand loading, not eviction. Loaded buffers keep their existing lifetime
for borrowed pointers and mapped pages. An active working set can still exceed
the fixed kernel heap; unrelated unopened files and inactive profiles now stay on
disk. No old profiles or game/runtime assets were deleted to obtain these results.

## Diagnostic additions

The browser profiler reports unloaded file counts/bytes and the largest unloaded
paths alongside resident capacity, heap walk/ledger agreement, allocation failures
and loader counts/bytes/errors. On the first heavy run, 431,233,570 bytes of unused
payloads remained unloaded even after both visits. These included standalone JS,
Quake data and old browser databases/startup caches.

The existing browser runner accepts `--rename-probe /root/path/to/large-file`
with `--shutdown-check`. It checks that the file is initially unloaded, uses the
real privileged browser IOUtils move operation with no-overwrite, waits for
committed writeback, then restores the original name. GDB must observe the same
disk ID/length, a different committed payload offset, zero resident capacity and
no dirty flags. A failed probe aborts the evaluation. It runs only in the private
clone; its debugger/setup interference is flagged in the report.

The cold-boot probe moved a 34,257,856-byte Quake file. Its disk ID stayed 1280;
the committed offset changed from 90,373,668 to 1,253,635,124 while capacity stayed
zero and `data_unloaded` stayed true. The browser restored the path and completed
two visits, six trusted input probes, resize, clean exit and shutdown. Full image
inspection afterward verified the original file bytes and metadata exactly.

Example (new output directory required):

```sh
make
python3 ports/zen/benchmark_browser.py \
  --data-image path/to/installed-private-checkpoint.img \
  --output build/perf/lazy-cache-check \
  --url local --repeat 2 --native-input --input-samples 3 \
  --diagnostics --diagnostic-samples 5 --shutdown-check --geometry-check \
  --rename-probe /root/usr/share/games/quake/id1/pak1.pak
```

The selected probe file must already exist and be unloaded; omit that option for
ordinary measurements. The main `data.img` is never booted in place.

## Runtime and integrity evidence

Evidence lives under `build/perf/zen-lazy-cache-20261106/`:

- `installed-first`: previously failing heavy checkpoint, two visits, six real
  native input probes, 22 content diagnostic cases, geometry, clean close and
  guest-originated shutdown; zero allocator failures.
- `install-first`: full current browser/font reinstall, 92 installed-file hash
  checks, two visits/six inputs/22 cases, resize/close/shutdown; zero allocator
  failures and 355,823,328 heap bytes free after workload.
- `cold-rename`: independent boot of the first result, unloaded-file relocation,
  two visits/six inputs/22 cases, resize/close/shutdown; zero allocator failures,
  424,613,168 free heap bytes and 484,434,535 bytes still unloaded.
- `final-stress`: ordinary kernel stress snapshot, a second full install with 92 hashes,
  committed unloaded-file rename, four page visits, twelve native inputs and
  44 content diagnostic cases; resize, clean close and guest-confirmed shutdown
  passed. Heap had 333,603,824 bytes free before close and 409,996,528 afterward,
  with zero allocation/realloc failures. The independent heap walk matched the
  ledger and covered the complete heap.
- `general-gui-final/report.json`: the existing 86-case performance GUI completed on
  the same final kernel: 84 OK, zero failures, two explicit skips (fork in the
  multithreaded GUI and opt-in DNS). It rendered 1197 frames, accepted its native
  probe, exported CSV and reported zero dropped UI events. Capture interference
  is flagged; these samples are regression evidence, not a matched speedup claim.
- Native file mappings passed three guests: eight-CPU shared aliases, private COW,
  cross-process/kill cleanup, synchronization/tail checks, independent remount and
  legacy namespace isolation.
- Native synchronous files passed three guests: concurrent O_SYNC writes,
  independent remount and legacy rejection. Existing protected VFS lock/caller
  cancellation and readlink acceptance also passed, restoring the ordinary kernel.
- The existing full-backend mount/read-ahead/legacy-version host check passed
  after adapting its payload inspection to the unloaded representation. Identity,
  readlink and mutation host contracts passed, including 32,000 concurrent
  rename/read operations and 8,000 atomic append writes. No assertions were removed. The older
  writeback host fixture still fails its previously observed private-page mock
  check (`shared store missing from file buffer`); native COW checks pass. Its
  mock writes directly into a borrowed cache page instead of taking a VM COW fault.

Read-only image inspection checks every live record's full content hash, size,
type, uid/gid, mode and timestamps. `installed-integrity.json` found 7,290 prior
records preserved, none missing; only the disposable benchmark configuration
changed. `rename-integrity.json` found all 7,469 prior records preserved, again
with only that configuration changed. Old profiles and the moved/restored game
file were unchanged. `install-integrity.json` found all 7,141 source records
retained; its nine changed paths are the explicitly refreshed browser package,
Terminal ELF and benchmark configuration. New records belong to the fresh profile. `final-integrity.json` subsequently
preserved all 7,619 records from the cold-rename checkpoint; only the benchmark
configuration changed and 227 fresh-profile records were added. Across the five
complete browser runs there were twelve visits, 36 trusted inputs, 132 content
case evaluations and 184 installed-file hash checks. After the final rename
synchronization correction, `rename-final` repeated the committed-unloaded-file
probe, two visits/six inputs/22 cases and resize/close/shutdown with zero failed
allocations, 440,830,512 heap bytes free and a complete matching heap walk.
Its final image inspection preserved all 7,846 prior records, with only the
benchmark configuration changed and 133 fresh-profile records added.
The final kernel SHA-256 is
`092ccd43b25b8569a3aaa94b61a1e3bb8ae1796994f4ad973e9a64b0200300d7`; its exact ELF and consolidated checks are retained as
`final-kernel.elf` and `verified-evidence.json`.

Raw JSON, events, profiles, matching kernel ELFs, source metadata, native logs and
image-inspection results are retained. These are QEMU and record/hash preservation
checks, not physical-device or power-loss durability proof. Kernel stack-debug
switches remain disabled by request.
