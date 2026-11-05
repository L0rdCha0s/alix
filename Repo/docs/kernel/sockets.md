# Native socket interface

The owned-descriptor runtime implements `socket`, `connect`, `send`, `recv`,
`getsockname`, `getpeername`, `getsockopt` and the supported `setsockopt` policies
for outbound IPv4 TCP. It uses the existing native transport and private file
table. `SOCK_CLOEXEC` and `SOCK_NONBLOCK` are applied before publishing the new
descriptor. Protocol zero selects TCP; unsupported families, types and protocols
return errors. The legacy global-descriptor profile returns ENOTSUP for these
entry points, preventing an integer from being interpreted in the other
namespace. Native upstream links require `socket-owned.o`.

Connect captures the fixed native IPv4 address through safe user copying into
a registered heap request. It starts a real connection, returns EINPROGRESS for
nonblocking sockets and uses normal native polling for completion. Numeric
connect does not occupy the DNS service. The original hostname-based TCP API
retains its own captured DNS stage.

`MSG_DONTWAIT` applies to an individual send/receive without changing shared
descriptor status. Receive `MSG_PEEK` copies the queued prefix under the TCP
lock and leaves receive cursors, size and event sequence unchanged. Requests
retain descriptions through alias close and process cancellation. Data buffers
and operation state remain in registered heap storage; no caller stack or user
address enters the event worker. `MSG_NOSIGNAL` selects the send error policy;
the native transfer test uses it but does not verify the SIGPIPE error path.
Unsupported message flags report EOPNOTSUPP. See the primary
[recv interface reference](https://man.openbsd.net/recv.2) for peek and per-call
nonblocking semantics.

Native `htons`/`ntohs`, `htonl`/`ntohl`, `inet_pton` and `inet_ntop` provide IPv4
conversion. Parsing accepts four decimal components, rejects ambiguous leading
zeros and malformed input, and preserves the destination on invalid input.
Formatting validates capacity before changing the destination. IPv6 conversion
and transport remain unsupported; address structures/constants are declarations
for the required interface surface.

Endpoint queries report the connection's captured source address and actual
ports; packet construction, checksum and receive matching use the same source
snapshot. Unconnected local queries return an unspecified address and zero
port, and peer queries report ENOTCONN. A short address buffer receives its
prefix and the complete required size. TCP descriptors report socket metadata
through `fstat`.

Socket queries expose type, domain, protocol, accept state, current allocated
receive capacity, the transport's send capacity and negotiated MSS. The current
transport has no Nagle coalescing and no keepalive/port-reuse facility. Queries
report those real policies; idempotent TCP_NODELAY enable and keepalive/reuse
disable succeed. Unsupported changes return errors without pretending the
requested feature was enabled. Buffer resizing and additional options remain
work.

Fatal TCP errors retain their specific errno. `SO_ERROR` takes a single-consumer
claim which is stored in a heap-owned deferred query lease. Successful copyout
commits that error read. Invalid or read-only reply/length storage releases the
claim without consuming the error; cancellation also releases it through the
persistent retirement worker. A generation check prevents an older commit from
clearing a newer error. Reading SO_ERROR clears the pending error, not the failed
transport state. Concurrent readers cannot all consume the same error.

`sys/socket.h`, `netinet/in.h`, `netinet/tcp.h`, `arpa/inet.h` and `sys/uio.h`
declare the native types and intended API. Remaining socket options, TCP
bind/listen/accept, TCP shutdown and complete TCP half-close behavior,
named local sockets, POSIX addressed messages and signal-aware
data-I/O interruption remain required work. Unsupported server/local/half-close
entry points now report their standard failure path, validating an existing
owned socket where applicable. They do not return success or alter outputs.
Connected `sendto`/`recvfrom` calls with no address use the existing TCP send/recv
backend. Gather writes have real [writev](vectored_io.md) acceptance.
Connected TCP `sendmsg`/`recvmsg` now gather/scatter real payloads through the
owned I/O executor. Headers and vector metadata are captured once into heap
storage; pending requests retain their metadata behind the bounded payload,
which is the only region the event worker accesses. The resumed caller performs
checked scatter copies and output-header updates. Capture failures submit no
send; failed receive copies may leave a prefix and the stream read can already
have consumed bytes. PEEK, per-call DONTWAIT, empty vectors, EOF and NOSIGNAL use
the existing TCP policies. Unsupported destination addresses and sent ancillary
data fail before I/O. Receiver ancillary output is empty for this TCP backend.
Native `AF_UNIX` stream socket pairs use two kernel-owned byte rings and the
existing readiness executor. NONBLOCK/CLOEXEC publication, read/write/send/recv,
poll/select, socket queries and local half-close operate on the same retained
descriptions across dup and native spawn. `sendmsg` captures SCM_RIGHTS into a
deferred ownership record before submission. The stream retains those references;
the receiving caller installs descriptors in its own table, honors
MSG_CMSG_CLOEXEC, reports truncated control data, and rolls back newly installed
slots on failed copyout. Workers never dereference caller addresses. Local
socket naming/listening and collection of unreachable descriptor-passing cycles
remain separate work. The actual Gecko parent now passes socket-pair creation
and launches its native socket subprocess; full browser startup remains ongoing.

Nonblocking TCP, UDP and local reads/writes and message operations execute their
bounded transport step in the calling syscall. Their registered request is completed
without an executor round trip; payloads, descriptor references and failed-copy
rollback still use the same request-owned records and deferred cleanup. Blocking
operations use the readiness executor. Poll/select first checks readiness in the
calling syscall and submits only when it must wait. The executor wakes promptly
on TCP, UDP and local readiness transitions, with a one-tick timeout fallback for
deadlines and other descriptor backends. A permanent sequence-numbered wait hub
prevents a transition between a readiness scan and sleeping from being lost;
transport notifications run after releasing transport locks.

TCP write readiness uses remaining retained-payload and remote-window capacity,
including space available while earlier bytes await acknowledgement. Short sends
are bounded to that capacity and rechecked under the transport lock. Appending
data preserves the oldest outstanding retransmission deadline and retry backoff;
the retention limit remains one MSS. Each event-executor scan also stops taking
the shared request-queue lock after its first empty result. A later submission
changes the readiness sequence and starts another scan.

Large owned TCP data requests reserve a transport-sized prefix before copying
user payloads. Writes use the negotiated MSS; reads use queued bytes, falling
back to one segment when empty. Requests at most 256 bytes keep their small
capture without an extra snapshot. The hint preserves positive counts and does
not decide readiness: the executor rechecks all state and may wait, return a
short prefix or report EAGAIN. It applies to scalar and vector stream APIs;
local/UDP limits remain separate. Native measurements and byte-counter semantics
are in [the continued performance report](../performance-pass2-2026-11-05.md).

Message preparation reserves four vector headers for ordinary calls and grows
only to the supplied vector count. Empty local sends omit ancillary ownership
records; receives retain the same SCM_RIGHTS capture and rollback owners.

The initial IPv4 DNS/netdb layer now has native lookup, ownership and cancellation
evidence; see [resolver.md](resolver.md) for capability and verification limits.

`make zen-socket-qemu-test` runs eight CPU-pinned connections in Alix. They
transfer 128 KiB and check blocking/nonblocking connect, atomic creation flags,
per-call EAGAIN without status mutation, repeated peek through aliases,
read-only/invalid buffer rejection, payload integrity and EOF. Serial evidence
is `build/test-out/socket-native-qemu.log`; the matching packet capture is
`socket-native-network.pcap`. The query checks exercise short replies, immutable
option policies, real refusal errno, failed-copy preservation and exactly one
consumer among eight CPU-pinned SO_ERROR readers. The harness matches all eight
reported endpoints to TCP SYN packets using tcpdump and writes a receipt with
the boot/ELF identities and capture hash. The original native
poll/TCP/cancellation fixture also passes after these changes.

`tests/tcp_owned_contract_test.py` runs production TCP ownership and peek checks
under ASan/UBSan and TSan, including claim cancellation, generation changes and
eight concurrent error consumers. Gecko's vendored Rust libc exports these
native address types and implemented socket entry points; its separate native
FFI fixture passes socket creation/type/local-address queries and size/offset
assertions. `tests/inet_contract_test.py` compares 20,000 IPv4
conversions against host libc and checks strict failures and output bounds
under ASan/UBSan. These targeted results do not establish complete POSIX socket,
NSPR/NSS, Gecko or Zen runtime acceptance.

The upstream Rust standard library now has an explicit Alix network backend
using these native APIs. `make zen-rust-std-net-qemu-test` verifies nine real
TCP connections and 294,912 received bytes, timed/nonblocking connects, refusal,
descriptor ownership and cloning, CLOEXEC, peek/EOF, lookup and hostname in
eight-CPU Alix. Unsupported listener/IPv6 capabilities return errors.
Evidence is `build/test-out/rust-std-net-qemu.log` with its network capture.
The actual Socket2 crate now compiles with its `all` feature for the explicit
Alix target. Its acceptance program exercises real TCP, polling deadlines,
atomic creation flags, cloning/shared nonblocking state, native FD ownership,
peek/EOF, gather/scatter message I/O and C/Rust address/poll/message layouts.
It also checks negative capability and capture-error paths. Reproduce with
`make zen-rust-socket2-qemu-test`; the serial and packet evidence are
`build/test-out/rust-socket2-qemu.log` and `rust-socket2-network.pcap`.
These TCP results do not establish server, local-IPC or complete browser support.
IPv4 datagram sockets, Rust std UdpSocket and the actual Quinn UDP crate now
have separate eight-CPU native acceptance. The shared event executor captures
payloads/endpoints and retains descriptions through blocked-call cancellation.
Classic addressed send/receive, connected gather/scatter, real buffer budgets
and explicit per-packet metadata are supported. See
[UDP transport](udp_transport.md) for scope, limits and packet evidence.
