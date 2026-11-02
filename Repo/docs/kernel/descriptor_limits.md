# Descriptor limits

The upstream runtime implements `getrlimit(RLIMIT_NOFILE)` and
`setrlimit(RLIMIT_NOFILE)` using the process-owned FD table. The native
`struct rlimit` contains two unsigned 64-bit values, totaling 16 bytes.
New user processes begin with soft and hard limits of 256 descriptors.

The soft limit bounds new descriptor numbers: allocation searches slots
below that limit. It applies to regular opens, sockets, directory streams,
duplication and atomic pipe publication. Existing descriptors remain usable
after either limit is reduced, including descriptors whose numbers exceed
the new limits. A reservation admitted before a concurrent reduction can
finish installing its already reserved descriptor. Failed admission occurs
before an open can create or truncate a file.

Limits and allocation reservations share the table lock. Queries return a
coherent pair; updates either replace both values or change neither. The
hard limit cannot exceed the table's fixed physical capacity of 256. Raising
a previously reduced hard limit requires the current native user ID to be
zero. Other callers can lower it, then adjust the soft limit within that
bound. A soft limit above the requested hard limit returns EINVAL; an
unauthorized hard-limit increase returns EPERM. A zero limit is valid.

`dup` reports EMFILE when it cannot allocate. The F_DUPFD variants additionally
reject a minimum at or above the current soft limit with EINVAL. `dup2` and
`dup3` reject an out-of-limit destination with EBADF; `dup2(fd, fd)` still
validates and returns an existing descriptor above the limit. Closing and
querying existing descriptors use the full physical table.

Native spawn clones both limits and inherited descriptors under the parent
table lock, while retaining the existing CLOEXEC filtering. Child changes do
not change the parent's policy. The child-process registry remains separate
from the public descriptor table and its allocation limit.

Syscall 71 (`FILE_IO`) adds GET_LIMIT and SET_LIMIT metadata operations. Their
arguments are resource, user pointer, exact 16-byte size, and zero reserved
value. The live caller copies the complete setter input before mutation and
checks query output through the normal user-copy machinery. There is no
worker, retained user address or shared caller-stack buffer. An incomplete
input copy leaves the limits unchanged; failed output copies follow the
general syscall rule that an earlier accessible page may already be copied.

RLIMIT_AS continues to report infinity because the kernel currently imposes
no aggregate address-space quota. That query now uses the checked metadata
path too. Setting RLIMIT_AS returns ENOTSUP. The legacy global descriptor
runtime rejects RLIMIT_NOFILE queries/updates with ENOTSUP, preserving its
namespace; it can still query the address-space policy.

`make zen-fd-limits-qemu-test` verifies enforcement, failed-truncate
preservation, atomic pipes, sockets, high slots, cross-page copy failure,
spawn inheritance/isolation and 512 operations on eight pinned CPUs. A second
guest verifies legacy rejection without private-policy mutation. The host
contract executes the production table and syscall code with 8,000 concurrent
operations under ASan/UBSan and TSan, including grandfathered reservations,
privileged changes, exact limits and inherited high descriptors.

Gecko's actual Rust libc fixture checks its resource ABI and enforced open
failure. The NSPR component fixture links its complete pthread I/O object and
calls PR_GetSysfdTableMax/PR_SetSysfdTableSize against the same native policy.
Complete NSPR initialization and the Zen application remain unverified.
