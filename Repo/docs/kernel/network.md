# Networking Architecture

The network stack is split into:

- NIC drivers (`src/drivers/*`) that push/pull raw Ethernet frames.
- A lightweight protocol stack (`src/net/*`) with a small interface registry.

## Interfaces (`include/net/interface.h`, `src/net/interface.c`)

`net_interface_t` represents a NIC (or virtual interface):

- Identity: `name`, `mac`, `present`, `link_up`
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

There is no generic UDP socket layer yet; UDP is used internally for DHCP/DNS/NTP.

## ARP + Routing (`src/net/arp.c`, `src/net/route.c`)

- `route.c` tracks at least a default route (gateway) and provides next-hop selection.
- `arp.c` maintains a neighbor cache and can:
  - Resolve next-hop MACs via ARP requests.
  - Announce the host IP→MAC mapping (`net_arp_announce`) so gateways learn/refresh the entry.

## TCP (`src/net/tcp.c`)

The TCP implementation is client-oriented:

- Small fixed socket pool (`NET_TCP_MAX_SOCKETS`).
- State machine sufficient for connect/send/receive/close.
- Per-socket RX ring buffer with backpressure thresholds.
- Retransmit and ARP retry timing based on `timer_ticks()`.

FD integration:

- `net_tcp_socket_open` allocates an FD via `fd_allocate(&g_tcp_fd_ops, socket)`.
- Reads/writes on that FD call into `tcp_fd_read/tcp_fd_write`, which block or return available bytes depending on the API.

Polling:

- `net_tcp_poll()` advances timers (retransmit, connect timeout, etc).
- It is called from a dedicated kernel process (`tcp_timerd` created in `src/kernel/kernel.c`) and also from some driver paths.

Receive performance:

- The IGB driver programs the 82576 interrupt registers through their legacy
  aliases (`ICR/ICS/IMS/IMC/IAM`) so both real hardware and QEMU's `igb`
  model deliver receive interrupts. A 100 ms poll remains only as a missed-IRQ
  watchdog.
- The IGB receive ring has 256 descriptors. TCP advertises a window-scaled
  receive window sized to stay within that ring's burst capacity.
- TCP negotiates RFC window scaling in the SYN, acknowledges every second
  full-sized in-order segment (or immediately for short/PSH/out-of-order
  traffic), and uses wait queues for blocking reads instead of tick polling.
- DNS A responses retain up to eight unique addresses in response order and in
  the cache. `ntpdate` tries each address with a two-second per-server timeout,
  so one unresponsive `pool.ntp.org` member does not fail the whole update.

## Higher-Level Protocols

- DHCP (`src/net/dhcp.c`) — assigns interface IPv4/netmask/gateway (used by shell `dhclient` command).
- DNS  (`src/net/dns.c`) — sends UDP queries and parses responses.
- NTP  (`src/net/ntp.c`) — queries time servers and feeds `timekeeping`.
- ICMP (`src/net/icmp.c`) — ping/echo handling.
- TLS  (`src/net/tls.c`, `src/net/tls_asn1.c`) — TLS client pieces layered on TCP sockets.
