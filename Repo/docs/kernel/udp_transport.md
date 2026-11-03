# Native owned UDP transport

`src/net/udp.c` implements an IPv4 datagram transport for the native network
executor. Sockets and queued packets use heap storage. A socket has explicit
owners; the IRQ-safe registry provides lookup/membership without creating a
legacy global FD. Final release unlinks the socket and releases its port before
freeing queued packets outside the registry gate. No process, user pointer or
caller stack is retained by the transport.

The transport supports binding, connected peer filtering, on-link/default-route
transmission, local delivery to assigned interface addresses, receive/peek,
whole-datagram consumption after a short read and zero-length datagrams.
Returned metadata includes source/destination, original length, interface,
TOS/ECN and TTL. TOS/TTL and buffer budgets are configurable. IPv4 and UDP
checksums, lengths and fragment fields are validated before queueing.

The current Ethernet MTU is 1500, with at most 1472 UDP payload bytes. Sends
set DF and return EMSGSIZE for larger payloads; IP fragmentation/reassembly,
IPv6, multicast and broadcast are not supplied by this implementation.
ARP/TX backpressure returns EAGAIN for the event executor to retry rather than
blocking its worker. Per-socket ARP state limits requests across nonblocking
calls, and polling withholds writable readiness while resolution is pending.
Driver callbacks receive a heap frame which they copy before return.

Receive queues are bounded by 128 packets, a per-socket byte budget and a shared
32 MiB packet-storage budget. Allocation/queue pressure drops a complete
datagram and increments the socket drop count. A zero-length datagram remains
readable even though its byte-availability query is zero.

`src/net/udp_ports.c` provides shared port leases for sockets and the built-in
DNS/NTP clients. Wildcard and specific-address conflicts are checked together;
the built-in DHCP client retains port 68. Lease tokens have stable heap/static
lifetime. The leaf gate never allocates, waits or calls another protocol.
DNS releases each pending lease on cleanup. NTP serializes its pending/result
state and refuses to steal a port already held by an application.

Both igb and RTL8139 dispatch UDP packets through the native transport before
the internal protocol fallback. The QEMU acceptance exercises the configured
igb path; compilation covers the alternate driver.

`make zen-udp-core-qemu-test` builds a temporary test kernel and uses
`run-via-agent.sh` through the native runner. Eight pinned protected services
send 256 datagrams and receive 256 host replies. Cases include zero/odd/max-MTU
payloads, retained ownership, peek/truncation, TOS/TTL and DNS/NTP port coexistence.
The host independently validates actual packet lengths/checksums, ECN/TOS,
TTL/DF, source ports and received metadata. A real DNS lookup runs while the
application ports remain leased. The following userspace TCP download/TLS
test passes, then the ordinary kernel is restored and checked for fixture removal.

Evidence is `build/test-out/udp-owned-qemu.log`, `udp-owned-network.pcap` and
its decoded capture. `build/ports/zen/udp-core/native-acceptance.json` records
the tested kernel/loader/user identities and packet proof. The exact tested
kernel is retained as `udp-core/validated-alix.elf`; it differs from the restored
ordinary kernel by the optional acceptance fixture.

`tests/udp_core_contract_test.py` executes production transport/port code under
ASan/UBSan and ThreadSanitizer with eight concurrent workers, 2,048 local
datagrams, malformed/checksum cases, ownership, queue bounds and allocation
failure. DNS's production asynchronous host contract uses the same port code;
its native netdb regression also passes.

The shared userspace bridge is `src/kernel/io/udp.c`. It uses the network event
executor, owned FD descriptions and registered heap requests. Workers access
captured payloads and endpoints; only the resumed caller copies to user output.
Final retirement releases queued packets and the port lease even when a caller
is killed during a blocked receive.

The owned runtime supports IPv4 `SOCK_DGRAM`, bind/connect, classic
sendto/recvfrom, connected read/write/writev and sendmsg/recvmsg, polling,
FIONREAD/FIONBIO, descriptor aliases and socket metadata. Receive supports
PEEK, DONTWAIT and bounded copying with MSG_TRUNC. Real receive/send budgets,
TOS and TTL are configurable. POSIX addressed/ancillary sendmsg and recvmsg,
IPv6, multicast, broadcast and segmentation/receive offload remain unsupported.

`alix_udp_send` and `alix_udp_recv` in `include/alix_network.h` provide explicit
per-packet TOS/source selection and a versioned 24-byte receive record. The
record contains actual source/destination, full datagram length, interface,
source port, TOS and TTL. IPv4 numbers use `a<<24|b<<16|c<<8|d`. Invalid source
overrides fail rather than being ignored.

Managed patch `0040` selects this native API for Gecko's actual Quinn UDP crate.
It preserves ECN/source selection and receive endpoint metadata, reports one
segment per send/receive and rejects unsupported segmentation or IPv6.
`make zen-rust-quinn-udp-qemu-test` runs the actual crate, Rust std UdpSocket
and public C socket API in an eight-CPU Alix guest. Its 256 host exchanges
cover zero/odd/max-MTU sizes, cloning, nonblocking I/O, buffers, peek/truncation,
safe-copy failures and wire-verified ECN/endpoints. A child blocked in receive
does not prevent another socket making progress; killing it releases its port.

Evidence is `build/test-out/quinn-udp-qemu.log`, `quinn-udp-network.pcap`, its
tcpdump decode and `quinn-udp-qemu.acceptance.json`. These are component runtime
results; the complete Gecko build and Zen browser startup remain unverified.
