# Native DNS and libc address lookup

Alix libc provides IPv4 `getaddrinfo`/`freeaddrinfo`, `getnameinfo`, legacy
host lookups and reentrant host/protocol/service lookup forms in `netdb.h`.
Address lists and canonical names are caller-owned heap allocations. Legacy
lookup results use per-thread TLS storage; caller-buffer variants validate
alignment and capacity before packing pointers and data. Protocols and common
services currently use built-in tables. IPv6, general PTR lookup, external
hosts/services databases and DNS-over-TCP fallback remain unfinished.

The current address list profile is IPv4 TCP, matching the implemented native
socket transport. It supports passive/loopback results, numeric host/service
flags, canonical names and configured-address filtering. Unsupported flags,
families, socket types and services return their address-lookup errors.
DNS NXDOMAIN, temporary server failures and malformed replies remain distinct
outcomes. See the maintained
[getaddrinfo reference](https://man7.org/linux/man-pages/man3/getaddrinfo.3.html)
for the address-list and flag interfaces; Alix's documented capability limits
do not imply full POSIX or NSPR conformance.

The user-facing DNS syscall copies the bounded name and per-call server values
into a registered heap request. Protected DNS service workers perform the
lookup and prepare a versioned value-only reply. No user output address, caller
thread/process pointer or caller stack enters the resolver worker. Failed
copyout and killed callers use the existing registered-I/O cleanup. The native
test kills a caller after its DNS packet is observed, then verifies fresh
lookups before and after the outstanding worker completes.

Receive callbacks validate IPv4/UDP lengths, fragmentation and nonzero UDP
checksums. They copy DNS payloads into bounded heap queues under the DNS pool
lock. The resolver owner alone parses answers, follows CNAMEs, retries and
updates its mutable request state. Port allocation and queue release share the
same lock. Queued duplicates are freed when the lookup ends. Response matching
checks interface, server address/port, transaction ID and question. This avoids
cross-CPU mutation of the resolver's scratch/request fields and prevents
receive callbacks from entering blocking CNAME/ARP work.

Default lookups snapshot DHCP/default servers and retain their configuration
generation. Cache entries preserve canonical spelling, and an older in-flight
lookup cannot repopulate the cache after the server configuration changes.
The internal per-call resolver interface supports an explicit server endpoint
without global configuration mutation; those replies do not populate the
default-resolver cache. Kernel callers must keep their synchronous resolver
owner protected through completion, as the upstream DNS service workers do.

`make zen-netdb-qemu-test` runs inside eight-CPU Alix with an independent
controlled UDP server. It verifies multiple A records, CNAMEs in one response
and follow-up queries, negative/truncated/malformed replies, mismatched question
rejection, TLS lookup storage, reentrant buffer limits, failed user copies and
caller cancellation. Eight connections then use resolved addresses for real
TCP transfers. The test retains the boot/ELF identities and capture hash in
`build/test-out/netdb-native-qemu.acceptance.json`. Its matching DNS packet
evidence is decoded using tcpdump's explicit domain decoder because the
controlled server uses an unprivileged port.

Production host tests pass ASan/UBSan and TSan for concurrent resolver ownership,
packet bounds/duplicate cleanup, counter wrap, cache generations, address-list
allocation rollback, caller-buffer packing, flags, error handling and TLS.
The actual Gecko-vendored Rust libc also passes native address-layout,
numeric/localhost lookup and name-output ABI checks. These results do not
verify default external DNS, complete NSPR/NSS, Gecko or Zen execution.
