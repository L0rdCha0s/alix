# Continued performance investigation, 5 November 2026

The prior pass and its six verified kernel fixes are retained in
[the first report](performance-pass-2026-11-05.md). This continuation uses fresh
native eight-CPU QEMU runs and the same protected data/firmware workflow.
Before-source snapshots, measurements and receipts are under
`build/perf/pass2-20261105`.

## Thread identity and mutex cost

The current suite reports an approximately 2.4 us uncontended pthread mutex
pair, compared with about 0.22 us for an uncontended read lock. Source review
found that `pthread_mutex_lock` and `pthread_mutex_unlock` each call
`pthread_self`, which queries the kernel every time. The next diagnostics add
raw and pthread identity-query costs, recursive/error-checking mutexes, write
locks, migration identity checks and a fork-child callback identity check.
Those checks use native self-info as an independent identity source. The raw
low-level thread-ID syscall remains available for applications which manage
raw TLS themselves.
