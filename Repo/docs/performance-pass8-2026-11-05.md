# Resident pathname metadata, 5 November 2026

Path stat previously submitted every request to a storage worker, including
resident metadata and missing entries. The existing descriptor-based path
already completed inline. The new bounded path lookup tries tree/data locks
once, parses captured path components without allocation and copies a coherent
snapshot while the tree lock protects node lifetime. It returns immediately
on bounded ENOENT/ENOTDIR results. Normal checked user copyout is unchanged.

The lookup budget is 256 visited nodes and 16 KiB of compared name bytes.
Directory link counting shares that node budget. Busy locks, callback-backed
nodes, writable shared mappings, first-time identity allocation, exhausted
budgets and symlink expansion leave the request unchanged for the protected
worker. No borrowed node or stack pointer crosses a thread boundary. Existing
captured caller identity and lookup policy remain in use. The same snapshot
helper also handles descriptor metadata, including bounded directory links.

Five new default cases cover fstat, missing paths, directories and symlink
follow/no-follow. They verify complete final metadata outside timing; missing
queries preserve a canary-filled output. Two opt-in 512-entry cases exercise
worker fallback. The default inventory now has 86 cases.

Five requested 150 ms rounds per case, two CLI boots before/after and a GUI pair,
produce these p50 batch-average microseconds per operation:

| Case | CLI before | CLI after | GUI before | GUI after |
| --- | ---: | ---: | ---: | ---: |
| stat | 112.304 | 15.258–15.869 | 263.671 | 18.920 |
| fstat | 15.258–16.479 | 13.427–21.972 | 20.751 | 14.648 |
| missing path | 112.304 | 14.648–18.310 | 244.140 | 16.479 |
| directory | 112.304–131.835 | 14.648–15.258 | 292.968 | 16.479 |
| follow symlink | 122.070 | 117.187 | 263.671 | 122.070 |
| no-follow symlink | 112.304–117.187 | 14.648 | 244.140 | 17.700 |

CLI ordinary stat improves about sevenfold. Its descriptive sample ranges with
a tick margin remain separate, as do missing/directory/no-follow cases. Fstat
and symlink-follow controls overlap in CLI. GUI and wide-directory worker
controls vary substantially between boots, so their reductions are not claimed
as equivalent-path improvements. The clock advances in 10 ms ticks; these are
eight-CPU QEMU observations, not physical-device or scanout measurements.

The existing post-measurement profiler now exposes path/descriptor metadata
request and inline counts. Diagnostic snapshots confirm:

| Case | Path requests | Inline |
| --- | ---: | ---: |
| ordinary stat | 40,961 | 40,961 |
| symlink follow | 5,120 | 0 |
| 512-entry directory | 5,121 | 0 |
| missing in 512-entry directory | 3,584 | 0 |

Counts include preparation, warmup and calibration. Profiles are not used for
quantitative comparison. The counter fields were added after matched timing
runs; their evaluator hashes are recorded separately.

Existing native versioned identities, symlink semantics, shared file mapping
coherence, checked copies, filesystem primitives and independent private-disk
remounts pass. Two host fixtures had stale helper dependencies: the identity
model now names dirty-node publication and the readlink fixture includes the
production retain helper. Their existing checks then passed. No new separate
test harness was added.

Full CLI and GUI runs complete all 86 cases with zero failures and expected
DNS/GUI-fork skips. The full GUI's 1,085 load frame intervals have p95 20 ms,
maximum 40 ms, no dropped events and no GUI error. Kernel stack checks remain
disabled. Evidence is under `build/perf/pass8-20261105`: raw reports/comparisons,
source snapshots/patch, assembly, profiles and native-check receipts. All matched
timing runs use the same app and evaluator, with unchanged inputs during each
run. No persistent data image is modified by these isolated checks.
