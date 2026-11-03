# System identity

`uname` and `gethostname` use metadata operations on syscall 71 (`FILE_IO`).
They are available in both the ordinary and upstream user runtimes and do not
interpret a file descriptor. The native `struct utsname` has five 65-byte
fields, totaling 325 bytes: sysname, nodename, release, version and machine.

The running kernel reports `Alix`, `development` and `x86_64`. This repository
has no formal OS release number. The version is `build:` followed by its
40-digit GNU SHA-1 ELF build ID. The kernel linker retains the note inside
the writable data load segment and includes it in the kernel data bounds.
This identifies the running kernel image independently of the application
or build host. It is an identity string, not an authenticity guarantee.

The hostname comes from `/etc/hostname`, matching the shell's `alix` fallback
for a missing or blank file. A protected storage worker opens the file using
captured caller credentials and retains its VFS node. The worker copies at
most 4 KiB under the node data lock into owned heap storage, then trims outer
spaces, tabs and line endings. A nonempty name may contain at most 64 bytes;
embedded NUL bytes and oversized input fail. In-place updates yield a coherent
file snapshot, while atomic replacement may yield either retained version.
No borrowed file data or caller stack storage crosses the worker boundary.

Only the live caller copies the completed reply to user memory. An inaccessible
output returns EFAULT. A hostname buffer must include space for its NUL byte;
an undersized buffer returns ENAMETOOLONG without copying a prefix. Worker
errors also leave output untouched. General checked copies can still copy an
earlier page before discovering a later inaccessible page, as documented in
[the syscall interface](syscalls.md).

`getgid` reads the current process's primary group through syscall 72
(`PROCESS`, operation 4). `getuid` retains its existing ABI. Alix currently has
one user/group identity pair; `geteuid` and `getegid` report that same pair.
Separate saved/effective identities, set-ID execution and Unix permission/ACL
enforcement remain unfinished.

Owned regular files now support fchown with captured-caller authorization and
persisted uid/gid. Root can change either field; an owner can retain its uid
and use its existing or primary group. See [VFS ownership](vfs.md#file-identity-and-ownership).

The native acceptance target is `make zen-system-identity-qemu-test`. It
correlates uname with the exact booted ELF build ID and kernel hash, checks
credentials, pointer errors and hostname limits, and performs 512 snapshots
on eight CPUs during 64 atomic hostname replacements. The host contract test
exercises the production parser, VFS copy and credential getters under
ASan/UBSan and TSan, including 28,000 concurrent snapshots. The Gecko-vendored
Rust libc FFI fixture independently checks its layout and calls these APIs
inside Alix.

`make zen-nspr-file-abi-qemu-test` exercises the configured NSPR metadata
converters and open function-pointer ABI. It checks native 64-bit open flags,
second-to-microsecond timestamps, large file sizes and timestamp overflow.
The error sink is instrumented and the functions are extracted from the
actual patched source with its configured headers. This is component
acceptance; the complete NSPR Unix source still requires shared mappings
and msync, and the full Zen application has not linked or run.
