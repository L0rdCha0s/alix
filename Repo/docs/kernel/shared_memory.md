# Named shared memory

The owned-descriptor libc implements `shm_open` and `shm_unlink` through the
registered storage-I/O path. Kernel-only VFS nodes hold the bytes in RAM. Their
names belong to a separate volatile namespace, without a filesystem path or
disk mount. Reboot discards the namespace.

Names start with one slash, have a nonempty single component and contain at
most 255 bytes including that slash. Up to 1,024 names can be linked at once.
Unlinked objects do not consume namespace entries. `O_RDONLY`, `O_RDWR`,
`O_CREAT`, `O_EXCL`, `O_TRUNC` and `O_CLOEXEC` are supported; unsupported flags
return `EINVAL`. Read-only truncation is rejected. Creation and the exclusive
existence check run under the VFS tree lock.

The public interface and lifetime rules are described in the
[shared-memory interface reference](https://man7.org/linux/man-pages/man3/shm_open.3.html).

Creation captures the caller's uid/gid and applies the low nine mode bits,
restricted by the process `umask`, before publishing the name. The initial mask
is zero and is inherited by spawned children. Existing-object access checks use the same VFS
owner/group/other policy as ordinary files. Only the current object owner or
root can unlink its name. Shared-memory descriptors always have `FD_CLOEXEC`;
spawn file actions can explicitly duplicate them into children.

The namespace, open file descriptions and mappings own separate references.
Unlink removes only the namespace reference. Existing descriptors and mappings
retain their node, including after creator termination. Recreating the name
creates a distinct zero-length object. `ftruncate` supplies zero-initialized
bytes, and the existing shared-page cache supplies coherent mappings across
processes. The normal file-mapping read/write access rules and current
live-mapping truncation restrictions still apply.

The caller reserves an FD slot before the worker can publish a new object.
Names, credentials and operation data are captured into registered heap storage.
Deferred descriptions hold the node through cancellation and final cleanup;
mapping references survive until the VM's remote TLB acknowledgements complete.
No worker retains a caller stack pointer, borrowed process pointer or user
address. The legacy global-FD profile returns `ENOTSUP` for both APIs.

`make zen-shared-memory-qemu-test` runs two private eight-CPU guests. It verifies
512 mapped updates, one exclusive creator, private creation mode, read-only
child mappings, close-on-exec behavior, unlink/recreate identity, killed-creator
survival and descriptor-pressure admission. An independent boot reads the
persisted disk marker while confirming the memory namespace is empty. Evidence
is in `build/test-out/shared-memory-qemu.log`,
`shared-memory-reboot-qemu.log` and `shared-memory.acceptance.json`.

`tests/shared_memory_contract_test.py` executes the production namespace code
under ASan/UBSan and TSan, checking allocation failure, owner/access checks,
concurrent exclusive creation, retained unlink references and leak-free cleanup.
These checks establish the memory service; full Gecko/Zen startup and local
IPC descriptor passing remain separate gates.
