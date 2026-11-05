# Networking Architecture

The network stack is split into:

- NIC drivers (`src/drivers/*`) that push/pull raw Ethernet frames.
- A lightweight protocol stack (`src/net/*`) with a small interface registry.

## Interfaces (`include/net/interface.h`, `src/net/interface.c`)

`net_interface_t` represents a NIC (or virtual interface):

- Identity: `name`, `mac`, `present`, `link_up`
- Native Ethernet MTU: `mtu` (currently 1500)
- IPv4 config: `ipv4_addr`, `ipv4_netmask`, `ipv4_gateway`
- TX hook: `iface->send(iface, frame, len)` set by the driver
- Counters: rx/tx bytes/packets/errors

Key APIs:

- `net_if_register(name, mac)` — allocate/find an interface slot.
- `net_if_set_tx_handler(iface, handler)` — install the driver TX function.
- `net_if_send_copy(iface, data, len)` — sends, cloning the buffer onto the heap if it points at a thread stack (DMA/async safety).

That stack/DMA guard is critical in an SMP kernel: callers must not hand NIC drivers pointers to stack memory that may be reused once the function returns.

## RX Dispatch (drivers)

Drivers parse Ethernet and dispatch to protocol handlers. Example (RTL8139):

- ARP (`eth_type == 0x0806`) → `net_arp_handle_frame`
- IPv4 (`eth_type == 0x0800`) → parse IP header then:
  - ICMP (proto 1) → `net_icmp_handle_frame`
  - TCP  (proto 6) → `net_tcp_handle_frame`
  - UDP  (proto 17) → port-based demux:
    - DHCP (67/68) → `net_dhcp_handle_frame`
    - DNS  (53)    → `net_dns_handle_frame`
    - NTP  (123)   → `net_ntp_handle_frame`

The native UDP transport now also has owned sockets and bounded datagram queues,
with common port leases shared by DHCP/DNS/NTP and future application sockets.
The userspace socket/executor and Quinn bridge remain unfinished. See
[UDP transport](udp_transport.md) for the current kernel scope and packet proof.

## ARP + Routing (`src/net/arp.c`, `src/net/route.c`)

- `route.c` tracks at least a default route (gateway) and provides next-hop selection.
- `arp.c` maintains a neighbor cache and can:
  - Resolve next-hop MACs via ARP requests.
  - Announce the host IP→MAC mapping (`net_arp_announce`) so gateways learn/refresh the entry.

Configuration updates and route snapshots now share an IRQ-safe gate, including
transactional IPv4 address/netmask/gateway replacement. Native callers can query
the selected interface and MTU through syscall 78 without a socket or packet.
See [route snapshots](network_routes.md) for ABI, ownership and verification.

## TCP (`src/net/tcp.c`)

The TCP implementation is client-oriented:

- Small fixed socket pool (`NET_TCP_MAX_SOCKETS`).
- State machine sufficient for connect/send/receive/close.
- Per-socket RX ring buffer with backpressure thresholds.
- Retransmit and ARP retry timing based on `timer_ticks()`.

FD integration:

- `net_tcp_socket_open` allocates an FD via `fd_allocate(&g_tcp_fd_ops, socket)`.
- Reads/writes on that FD call into `tcp_fd_read/tcp_fd_write`, which block or return available bytes depending on the API.

The native descriptor backend also has an owned socket mode. `net_tcp_socket_open_owned`
allocates a socket without a legacy global FD or a borrowed creator thread.
Explicit get/put references prevent pool-slot, buffer and wait-queue reuse until
the final protected put. Connected transports then remain timer-owned through
FIN/ACK or a bounded close timeout; they cannot be resurrected by get. Queue
wake/debug continuations hold a transport lease and bounded preemption guard
across temporary TCP-lock release, preventing cancellation or reset from
stranding their ownership or reinitializing a queue they are using.
Reference overflow fails instead of wrapping. Legacy
reset/release cannot recycle an owned slot; transport close preserves its owners.
Callers must register each acquired owner before allowing cancellation. Deferred
descriptor finalizers will provide the protected final-put context.

`net_tcp_socket_owned_snapshot` reads reference count, buffered bytes, event
sequence and connection/read/EOF/error/write readiness under the TCP lock. These
are internal value snapshots; public `dup`, `fcntl`, poll and cancellation-safe
socket syscall routing still need integration with the private FD table and an
event-driven network executor's syscall entry points. Indefinite reads must not
occupy the storage worker pool.

The protected event executor and its TCP adapter are now implemented.
`io_event_service` gives every admitted request one bounded nonblocking step per
scan, retaining pending requests in a heap array. A separate protected worker
drains cleanup, including canceled/abandoned callers. Idle workers sleep on the
service's availability queue; pending readiness is polled at the native clock's
sleep granularity. Shutdown cancels, completes and joins both workers, then
waits for callers to release their waiter ownership before allowing destruction.

`io_tcp_execute` opens deferred owned descriptions and handles numeric IPv4
connect, read, partial write and available-byte snapshots. Its continuation
state, data and retained inputs live in registered request storage. It does not
perform DNS or storage waits on the event worker. An atomic description read
gate serializes shared readers without blocking another executor. Fine-grained
socket errors and POSIX address/options APIs remain unfinished. Syscall 71 now
routes process-owned descriptors through this executor, with DNS on a separate
protected service; a descriptor pin survives the DNS-to-connect transition.

`make io-event-service-test` executes active production sources with eight host
callers, 1,024 jobs, pending/canceled requests, independent/reentrant cleanup,
bounded admission, shutdown ownership and allocation/factory failure rollback.
Plain, ASan/UBSan and TSan passed. `make event-tcp-qemu-test` also passed the
real kernel: three socket readers blocked while another socket transferred
16 KiB; killing the three callers left their output untouched, released the
registered requests and allowed clean executor shutdown. Packet checks verified
all five TCP connections' handshakes and bidirectional FIN/ACK, plus both HTTP
streams. The ordinary download and eight-CPU TLS fixture passed afterward, and
the runner restored the ordinary kernel.

`make tcp-owned-contract-test` executes the production ownership code with
80,000 concurrent get/put cycles, allocation-failure rollback, overflow, legacy
mode and live-slot reuse checks; ASan/UBSan and TSan also passed. The separate
`make tcp-owned-qemu-test` uses disposable disks through `run-via-agent.sh`,
checks 8,192 reference cycles on all eight CPUs, and verifies a real 16 KiB HTTP
body through an owned connection after dropping its original reference. It also
runs the event-executor cancellation fixture, then downloads and runs the existing eight-CPU TLS fixture, restores the ordinary
kernel, and verifies that its optional boot hook is absent. Evidence is in
`build/test-out/tcp-owned-qemu.log`; `tcpdump` on `tcp-owned-network.pcap`
confirmed handshake, contiguous response sequence ranges and FIN exchange.

One captured run passed TCP acceptance and the legacy download but stalled in
the subsequent TLS fixture. A later private-FD run reproduced stranded RUNNING
threads with no CPU owner or run-queue entry. Analysis against its retained
kernel ELF identified a wake-before-park scheduler race, described in
[process.md](process.md). The deterministic regression failed before the fix;
the forced native wake test, private-FD transfer/capture and following eight-CPU
TLS fixture passed afterward. Earlier scheduler/register/packet evidence remains
in `build/test-out/tcp-owned-tls-capture-timeout.*` and
`build/test-out/private-fd-pre-wakefix.*`. Unexpected native failures retain
their exact kernel ELF plus scheduler/run-queue and context data.

Polling:

- `net_tcp_poll()` advances timers (retransmit, connect timeout, etc).
- It is called from a dedicated kernel process (`tcp_timerd` created in `src/kernel/kernel.c`) and also from some driver paths.

Receive performance:

- The IGB driver programs the 82576 interrupt registers through their legacy
  aliases (`ICR/ICS/IMS/IMC/IAM`) so both real hardware and QEMU's `igb`
  model deliver receive interrupts. A 100 ms poll remains only as a missed-IRQ
  watchdog. An IRQ that interrupts a generic lock owner records pending work
  after acknowledging the cause; the next safe timer tick drains it instead
  of waiting for that watchdog. Idle ticks do not poll the hardware.
- The IGB receive ring has 256 descriptors. TCP advertises a window-scaled
  receive window sized to stay within that ring's burst capacity. Reclaimed
  descriptors are returned to hardware in groups of at most 32, with a final
  tail update before leaving every receive pass. This reduces RX doorbell
  MMIO writes during a burst while promptly returning short bursts and
  malformed descriptors and preserving the 256-packet interrupt budget.
- TCP offers RFC window scaling in the SYN and enables it only when the peer
  also offers it. QEMU's Slirp backend in the download benchmark does not
  offer scaling, so its negotiated receive window remains at most 65,535
  bytes even though the guest SYN includes the option.
- TCP acknowledges every second in-order data segment, or immediately for
  PSH/out-of-order traffic and FIN. An unpaired segment has a 10 ms ACK
  deadline. The peer's MSS is an upper bound, not a promise about packet
  sizes: the benchmark's Slirp stream carries 1440-byte payloads after
  negotiating MSS 1460. Treating every shorter packet as urgent previously
  caused one ACK and TX doorbell per received packet throughout the ZIP.
- Receive checksums are verified directly in the immutable NIC buffer. TCP
  wakes blocking readers when an empty receive buffer becomes nonempty,
  plus close/error events; packets arriving behind buffered data do not
  repeatedly acquire the scheduler lock. The read-event sequence still
  closes the readiness-check-to-sleep race.
- `/proc/sys/net/igb_stats` exposes cumulative IRQ/deferred-IRQ counts, packets
  drained by IRQ versus polling, receive-batch counts and maximum size, and
  RX tail writes and deferred versus watchdog poll counts. Counters avoid per-packet serial
  logging while measuring whether the watchdog is carrying receive traffic.
- DNS A responses retain up to eight unique addresses in response order and in
  the cache. `ntpdate` tries each address with a two-second per-server timeout,
  so one unresponsive `pool.ntp.org` member does not fail the whole update.

The ACK policy follows [RFC 5681 section 4.2](https://www.rfc-editor.org/rfc/rfc5681.html#section-4.2).
Window scaling requires an offer from both endpoints, as specified in
[RFC 7323 section 2.2](https://www.rfc-editor.org/rfc/rfc7323.html#section-2.2).

## Download completion and profiling

`wget --profile [iface] <url> [destination]` reports a single serial diagnostic
with setup, blocking reads, buffered appends, reservation, final flush, total
time, and read-call count. These measurements use the kernel tick clock; compare
host wall times for end-to-end benchmarks because IRQ work and tick granularity
affect attribution of short phases.

For a mounted destination, `Saved` is printed only after file data, directory
ancestors, filesystem metadata, and the device cache have been flushed. Failure
to persist is an error. A RAM destination requires no disk I/O. The generated
binary updater downloads `user-elfs.zip` to `/tmp`, then extracts its contents
to `/root/usr/bin`; the archive transfer itself is RAM-backed.

The updater packages `build/user/runtime/*.elf`, separate copies made with
`x86_64-elf-strip --strip-debug`, and bootstraps with `runtime/unzip.elf`.
These copies retain all program headers, loaded bytes, entry addresses and
runtime symbols, including `.symtab`. Full DWARF remains in the original
`build/user/*.elf` files: use those originals with `x86_64-elf-addr2line` or
GDB when resolving source lines from guest addresses. The kernel ELF loader
uses program headers and does not load DWARF sections.

The measured 20-binary archive shrank from 45,693,225 to 9,892,670 bytes by
omitting this unused debug data, and extracted files shrank from 109,044,624
to 24,755,960 bytes. `make runtime-archive-test` verifies the original/debug
and runtime copies against every program header, every loaded byte and named
runtime symbol, checks archive membership and contents, and rejects a
deliberately corrupted executable copy.

`make network-download-perf-test` boots isolated copies of the data disk and
firmware through `run-via-agent.sh`, downloads the exact archive to RAM and disk,
verifies hashes, then stops QEMU immediately after the final disk download
reports success and checks disk contents again after a cold boot. There is no
guest sync or shutdown between `Saved` and that stop. The Python harness also
supports `--pcap` (analysed with `tcpdump`) and exposes this durability check as
`--powercut-after-save`. Evidence is saved
under `test-out/network-<label>/`, outside the exported boot volume.

### Measured verification (2026-09-07)

On QEMU 10.1.2, eight-core TCG, the existing `vmnet-shared` backend, and a
local HTTP server bound to its gateway, measured command-to-`Saved` times were:

| Archive and implementation | RAM `/tmp` | Disk `/root` |
| --- | ---: | ---: |
| Original 45,693,225-byte ZIP, original code | 7.015 s | 6.946 s |
| Same ZIP, receive/copy/writeback fixes | 4.784 s | 2.839 s |
| 9,892,670-byte runtime ZIP, fixed code | 1.411 s | 0.890 s |

The original command did not guarantee a disk flush before `Saved`; the fixed
disk times include it. The runtime ZIP survived an immediate QEMU stop and
cold reboot with an identical hash. Its stripped bootstrap ran, extracted all
20 ELFs with matching hashes, and the installed `playsound` executed a test
WAV. Complete results are in
[`network-packaged-vmnet-install/result.json`](../../test-out/network-packaged-vmnet-install/result.json).

Separate packet captures on the user-network backend showed approximately
16,000 ACKs for 31,733 data segments after the change (about 32,000 before),
and roughly one RX tail-register write per 32 packets. There were no repeated
payload bytes or zero-window stalls in those captures. Unaligned kernel-copy
measurements over 44 MiB repeated four times fell from 5,100 to 680 ms while
retaining general-register-only code. Filesystem behavioral tests verified
that an atime update on an 8 MiB file writes 512 bytes instead of 8,389,632,
and that 32 adjacent chunk entries use one sector write instead of 32 reads
and 32 writes.

## Higher-Level Protocols

- DHCP (`src/net/dhcp.c`) — assigns interface IPv4/netmask/gateway (used by shell `dhclient` command).
- DNS  (`src/net/dns.c`) — sends UDP queries and parses responses.
- NTP  (`src/net/ntp.c`) — queries time servers and feeds `timekeeping`.
- ICMP (`src/net/icmp.c`) — ping/echo handling.
- TLS  (`src/net/tls.c`, `src/net/tls_asn1.c`) — TLS client pieces layered on TCP sockets.

### Deferred receive completion at syscall return

An IGB interrupt acknowledged during a generic preparation guard marks receive
work pending. The unlocked, interrupt-enabled syscall-return boundary now calls
`igb_poll_deferred` to drain the existing bounded RX path promptly. The ordinary
IRQ path and the timer/watchdog remain available. `syscall_return_polls` in
`/proc/sys/net/igb_stats` identifies these drains. This avoids adding a full
100 Hz tick to short exchanges while preserving scheduler lock ordering.

Unopened TCP sockets reserve 64 KiB of receive heap space. Connect expands that
buffer to 5 MiB before sending the SYN. SO_RCVBUF reports the actual current
allocation; normal connected receive/window policy retains its full capacity.
See [the measured performance pass](../performance-pass-2026-11-05.md).
