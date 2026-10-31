# Native readlink public wrapper

`filesystem_posix.c` supplies the POSIX `readlink` entry point over the genuine
native syscall 66 bridge owned by the protected VFS worker integration. It
returns the exact byte count without adding NUL, preserves errno on success,
and converts a negative kernel errno into `-1` with thread-local errno set.
No filesystem lookup, caller pointer or asynchronous request is retained here.

`python3 ports/zen/filesystem/prepare_readlink.py` stages the public declaration,
new user-libc module and USER_COMMON registration under
`build/ports/zen/readlink-posix`. It checks the patch from the actual parent git
root with the explicit `Repo` prefix. Apply only after the raw syscall bridge is
integrated, and regenerate first to preserve concurrent Makefile/header changes.
From the Repo directory the application command is:

```sh
git -C .. apply --check --directory=Repo Repo/build/ports/zen/readlink-posix/readlink-posix.patch
git -C .. apply --directory=Repo Repo/build/ports/zen/readlink-posix/readlink-posix.patch
```

Verify the active files against the manifest's after hashes. A plain apply from
this git subdirectory can silently skip paths, so exit status alone is not
evidence that the integration occurred.

`tests/readlink_test.c` uses the kernel worker fixture's actual symlinks under
`/tmp/vfs-owned-test`, with heap storage. It checks raw targets, exact/truncated
capacity, unchanged bytes after the result, final-link versus intermediate-link
resolution, non-links, missing paths, invalid output memory and zero capacity.
Its `READLINK_TEST: PASS` marker is meaningful only after execution in Alix
with syscall 66 and the kernel fixture installed.

The public wrapper and fixture compile with native `-Wall -Wextra -Werror`
against the real staged syscall-66 headers. The wrapper's only unresolved
symbols are native `sys_readlink` and `__errno_location`; it has not yet been
claimed as runtime-verified before the protected I/O integration.
