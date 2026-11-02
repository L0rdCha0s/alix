# Native descriptor controls

The owned libc profile implements `ioctl` using `SYSCALL_FILE_IOCTL` on the
process-private descriptor table. It never falls back to a matching legacy
global integer. The legacy libc entry point returns ENOTSUP without reading
variadic pointer arguments or modifying private descriptors.

| Request | Argument | Result |
| --- | --- | --- |
| FIONBIO | Pointer to native 32-bit int | Zero clears NONBLOCK; any other value sets it. |
| FIONREAD | Pointer to writable native 32-bit int | Non-consuming readable-byte snapshot. |
| FIOCLEX | None | Sets this descriptor slot's CLOEXEC flag. |
| FIONCLEX | None | Clears this descriptor slot's CLOEXEC flag. |

FIONBIO updates only the selected mutable bit with a CAS loop. Append and
access-mode bits remain intact, and aliases observe the shared description
status. CLOEXEC changes are per slot and do not alter duplicate slots.
These controls do not require event/storage admission.

FIONREAD supports native pipes (both ends), IPv4 TCP sockets and regular VFS
files. Pipe queries snapshot the ring under its lock; TCP snapshots include
peeked data and do not claim pending SO_ERROR. Regular-file queries serialize
the shared offset gate with a metadata snapshot, return max(size-offset,0)
and do not advance the offset. The public signed-int result saturates at
INT32_MAX. Console, directory, audio and other unsupported descriptions return
ENOTTY for this query.

## Ownership and user copies

The syscall validates the exact four-byte payload for pointer controls; the
no-argument controls reject nonzero pointer/size fields. FIONBIO captures its
input in the live caller before changing status. Read-only input is valid.
Invalid input leaves flags unchanged.

FIONREAD pins the original open description in a registered heap-owned
request. Pipes/TCP use the bounded event executor; files use the protected
storage service because the offset gate can wait. Workers receive no caller
process, user-pointer or stack ownership. Only the live caller writes the
four-byte result after completion, using checked user-copy primitives.
Read-only or invalid output returns EFAULT without consuming bytes or pending
socket errors. Closing/reusing an integer cannot retarget the captured owner.

Unknown requests return ENOTTY after validating the private descriptor;
invalid descriptors return EBADF. `winsize` and the size-request constants
describe an ABI, but Alix has no TTY backend: those requests return ENOTTY.

The upstream runtime links exactly one ioctl-owned.o and excludes legacy
ioctl.o. The native target driver checks this with its other namespace guards.

## Validation and remaining integration

`make zen-ioctl-qemu-test` checks regular-file counts/offsets, exact output
width, invalid/read-only pointers, flags and aliases, full/empty pipes and EOF,
then 768 pipe snapshots across eight pinned workers. A second guest verifies
legacy rejection and unchanged private flags.

The eight-CPU socket fixture adds FIONBIO/FIONREAD checks around real 16 KiB TCP
payloads, MSG_PEEK, EOF and the existing single-consumer pending-error test.
Its endpoint metadata still matches a tcpdump-verified packet capture.
The actual Gecko-vendored Rust libc fixture validates request/structure ABI,
regular-file/pipe byte counts, flag controls and unsupported TTY results.

Host ASan/UBSan and TSan contracts include 20,000 partial flag updates, 28,000
serialized file-byte snapshots, EOF/large-offset/bounds/error cases and the
existing deferred-descriptor lifecycle suite. Pipe contracts also check
metadata snapshots alongside ring wrap, atomic admission, EOF and failures.

Gecko configuration and the native compiler-driver link checks pass with the
new object. NSPR's actual Unix source advances past this header and currently
stops at missing sys/utsname.h. Full NSPR/NSS/Gecko linkage and Zen execution
remain unverified.
