# Native gather writes

Connected TCP also supports `sendmsg` and `recvmsg` through appended private
I/O operations. A registered request owns its captured header/vector trailer
and bounded contiguous payload. One TCP operation gathers a write or supplies
bytes that the resumed caller scatters into its captured destinations. Empty
vectors are skipped; aggregate lengths above INT64_MAX and more than 1,024
vectors fail before submission. Payload capacity is bounded by the 64 KiB
request limit after metadata; larger stream transfers can return a short
prefix. Destination addresses and sent ancillary data remain unsupported.
See [sockets](sockets.md) for checked-copy, per-call flag and cancellation scope.

`tests/socket_message_contract_test.py` executes the production preparation and
completion paths under ASan/UBSan, including bad later vectors, overflow,
allocation/admission/submit/cancellation faults, scatter/header copy failures,
EOF and SIGPIPE/NOSIGNAL ownership. The actual Socket2 eight-CPU guest verifies
gather/scatter over real TCP, source-header faults before sending and suppressed
SIGPIPE after EOF. This does not supply general descriptor `readv` or local
socket descriptor passing.

The owned descriptor runtime implements `writev` through the private file I/O
syscall. `struct iovec` and the native wire record both contain a pointer and
64-bit length, for a total of 16 bytes. Up to 1,024 vectors are accepted. Existing
operation numbers are unchanged; the new operation is appended to the private
file namespace. The legacy runtime returns `ENOTSUP` without using a matching
private FD integer. `readv` remains separate, unimplemented work.

The kernel pins the open description, captures the vector headers into owned
heap storage, and checks that their total fits `ssize_t`. It then copies a bounded
prefix of the input bytes into one registered I/O request. Header and payload
copies use the checked user-copy resolver. A failed capture submits no write and
does not advance the file offset. Zero-length entries do not dereference their
base pointers. All temporary vector metadata is freed before submission and
before the preparation guard is released; no worker retains a vector array,
caller stack or input address.

The request uses the existing file, pipe, TCP, audio or standard-stream write
backend. It has one offset/append gate and, for synchronous files, one persistence
operation. Pipe writes whose combined length is at most `PIPE_BUF` retain the
pipe's atomic admission rule even when split across vectors. Larger inputs may
return a short prefix bounded by the 64 KiB request limit, less the backend
header. Nonblocking waits return `EAGAIN` when no permitted write can proceed.
The pipe error path raises `SIGPIPE` and returns `EPIPE` if its handler returns.
Success preserves `errno`; failures return `-1` and set it.

The standard gather ordering and short-write behavior are described in the
[writev manual](https://man.openbsd.org/writev.2).

`make zen-writev-qemu-test` passes in an eight-CPU Alix guest. Its
`build/test-out/writev-qemu.log` checks 512 atomic pipe records and 512 concurrent
append records, count/overflow validation, invalid later vectors, protected
cross-page headers and payloads, zero entries, bounded large writes, nonblocking
atomic admission and caught `SIGPIPE`. Worker arguments and records are heap-owned.
`tests/writev_contract_test.py` executes the production preparation function with
modeled I/O boundaries under ASan/UBSan, injecting copy, allocation, admission,
submission and cancellation failures. The full NSPR runtime suite separately
exercises its real TCP `PR_Writev` path and host echo readback.
