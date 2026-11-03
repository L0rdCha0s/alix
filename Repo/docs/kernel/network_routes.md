# Native outgoing route and MTU queries

`alix_net_route_ipv4` in `alix_network.h` returns the real outgoing interface,
configured MTU, source IPv4 address and next hop without opening a socket or
transmitting. IPv4 numbers use `a<<24|b<<16|c<<8|d` for `a.b.c.d`; use
`ntohl(address.s_addr)` when starting with a C `struct in_addr`.
The version-1 reply is 24 bytes with an eight-byte NUL-terminated interface name.

Syscall 78 takes the numeric destination, reply pointer and reply capacity.
It validates the shape, allocates a small heap reply with preemption deferred,
takes the bounded route snapshot, performs checked user copying and frees the
reply before restoring preemption. No worker retains caller storage. Invalid
sizes/destinations return EINVAL, invalid output returns EFAULT, allocation
failure returns ENOMEM and an unavailable route returns ENETUNREACH.
Checked copies follow the existing prefix-on-copy-failure contract.

The interface registry and routing configuration share an IRQ-safe spinlock.
DHCP address/netmask/gateway replacement is one transaction. Route selection,
link changes and the returned values use the same gate, so a query cannot mix
one configuration's source address with another configuration's gateway.
Interface slots are initialized before their count is atomically published;
their identities and storage remain stable. The gate never covers allocation,
driver callbacks, user copying, network transmission or a blocking wait.

Current interfaces use the native Ethernet MTU of 1500. There is no jumbo-frame
configuration API, IPv6 routing, loopback or multicast interface. Queries for
those unsupported destinations fail. This is an interface MTU query rather
than path-MTU discovery. The existing route selection still chooses an on-link
interface before falling back to the configured default route.

Gecko's actual `mtu` crate has an explicit Alix backend using this API, with no
netlink/BSD route-socket emulation or foreign target-family selection.
`make zen-rust-mtu-qemu-test` verifies 512 queries on eight pinned guest CPUs,
the actual interface/source address, local/default routing, C/Rust ABI, checked
output/capacity errors and unsupported IPv6/loopback results. Evidence is
`build/test-out/rust-mtu-qemu.log` with its boot-image sidecar.

`tests/network_route_contract_test.py` exercises the production registry and
route code under ASan/UBSan and ThreadSanitizer: 56,000 coherent snapshots during
8,000 configuration changes, on-link/default choices and link-down behavior.
`tests/network_route_syscall_contract_test.py` faults allocation and copying
while checking heap cleanup, output preservation on no-route errors and
preemption balance. The existing packet-correlated TCP guest regression passes
with the new configuration gate.
