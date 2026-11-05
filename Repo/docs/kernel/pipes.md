# Process-owned pipes

The upstream runtime's `pipe` and `pipe2` use operation `SYSCALL_FILE_PIPE` on
syscall 71. A successful call publishes the lowest two free private descriptor
slots together. Failure leaves both slots and the output array unchanged;
copyout failure removes only slots still holding the new descriptions.
`pipe2` supports `O_CLOEXEC` and `O_NONBLOCK`; other flags are rejected.

Each pipe owns a 16 KiB heap ring and two deferred open descriptions. Duplication
and table inheritance retain those same descriptions. Closing a slot removes it
immediately; its endpoint stays alive through other aliases and registered I/O.
Final writer retirement permits EOF after buffered bytes drain. Final reader
retirement makes a write fail with `EPIPE`, and the live calling thread receives
`SIGPIPE` after its I/O record is released. Default, caught, ignored and masked
dispositions use the existing native signal machinery. The native pipe fixture
specifically checks default, caught and ignored dispositions.

The event executor performs bounded readiness steps for both pipes and TCP.
Blocking empty reads with writers and writes without sufficient space stay pending,
leaving the executor available for other requests. Writes of at most 4096 bytes
are committed together; larger writes can return a partial count. The ring lock
protects each copy and its cursors. No caller stack, user address, or process
pointer enters a worker. Requests canceled by process termination use the
existing registered-request cleanup and deferred description retirement.
With `O_NONBLOCK`, an empty live pipe or insufficient space returns `EAGAIN`;
small writes still require room for their entire atomic record. `F_GETFL` and
`F_SETFL` operate on shared description status, so aliases and inherited slots
see changes together. Access mode remains immutable; CLOEXEC belongs to each
slot independently. Creation publishes NONBLOCK and CLOEXEC atomically.

Both endpoints report FIFO metadata. Reads on the writer and writes on the
reader fail with `EBADF`; seeking/pread fail with `ESPIPE`. Zero-length valid
operations return zero. The upstream profile supplies these APIs; base Alix
applications retain their legacy descriptor ABI.

`make pipe-contract-test` covers wrap/order, small-write backpressure, EOF/EPIPE,
allocation and second-description admission failures, atomic pair rollback,
reference saturation, CLOEXEC inheritance and eight concurrent host writers.
Plain, ASan/UBSan and TSan pass. `make zen-pipe-qemu-test` passes separate native
eight-CPU guests: 512 noninterleaved records, 4096-byte backpressure, three idle
readers while a fresh pipe progresses, EOF after final aliases, capacity
rollback, and caught/ignored/default SIGPIPE. Serial evidence is in
`build/test-out/pipe-qemu.log` and `pipe-default-qemu.log`.

Native [poll integration](poll.md) now covers pipe input, atomic write space,
hangup, signal interruption and cancellation of a killed waiter. The native
`fd-stream-native-qemu.log` fixture also passes nonblocking full/empty pipes and
atomic small-write admission. Select and general signal-interrupted data I/O remain unfinished. A pipe
transfers bytes; native child spawn/wait and exec inheritance acceptance remain
separate work.

Ready pipe reads/writes now try the existing bounded ring step in the calling
syscall, retaining registered request ownership, checked copies and SIGPIPE
handling. A step which needs readiness is submitted to the existing executor.
This removes scheduling trips for already available data/space without changing
blocking, EOF, atomic-write or cancellation policy.
