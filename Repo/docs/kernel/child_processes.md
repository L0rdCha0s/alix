# Native child launch and waiting

Syscall 72 exposes native argv launch and child waiting. `alix_spawn_argv` starts
an owned-descriptor Alix ELF with a copied argument vector and an empty
environment. It returns the actual child PID. `waitpid` supports a positive PID
or `-1` for any child, optional `WNOHANG`, and a nullable status destination.
`wait` is the any-child wrapper. Group selectors and stopped/continued-job flags
return `ENOTSUP`. Caught-signal interruption follows the current registered-I/O
delivery policy; `fork` and in-place `exec` remain separate capabilities.

Arguments have at most 256 entries and share the bounded 64 KiB request buffer
with their offsets and copied executable path. User pointers are fetched through
the safe-copy helpers before submission. A launch captures an owned cwd,
credentials and private descriptor snapshot under its preparation guard. The
extended launch interface also captures environment strings and ordered file
actions. It snapshots descriptors before applying actions, then filters CLOEXEC
entries before publishing the child. Worker state and environment vectors are
heap-owned. The new stack belongs to the child, including its copied environment
and pointer vector; CRT imports that environment before preinit/constructors.

`posix_spawn` and `posix_spawnp` expose this extended interface through
`include/spawn.h`. File actions support ordered close, dup2, open and
`posix_spawn_file_actions_addchdir_np`. A self-dup
clears CLOEXEC, and open preserves requested CLOEXEC. PATH lookup uses a snapshot
of the parent's environment and applies actions only once across candidates.
Explicit empty environments remain empty. Signal masks and default-disposition
attributes are supported; ignored dispositions otherwise survive launch and
caught handlers reset. RESETIDS uses Alix's existing single identity policy.
Process groups and scheduling attributes return `ENOTSUP` during spawn.

The owned launch context also snapshots the process creation mask. Open actions
apply their requested mode through that snapshot, and the resulting child
inherits the same mask. Later parent or child `umask` calls cannot alter the
other process's state. Unsupported set-ID/sticky creation requests fail before
launch instead of silently changing their requested policy.

`POSIX_SPAWN_CLOEXEC_DEFAULT` marks every descriptor in the child's private
snapshot close-on-exec before file actions run. Explicit dup2/self-dup actions
retain their destinations, including standard streams when requested. Sources
remain available until actions finish. The parent's flags never change, and
descriptors opened concurrently after the snapshot cannot leak into the child.

The chdir action copies its path into the action object, then the syscall copies
it into registered launch storage before submission. The protected loader
resolves it against the launch record's current cwd, retains a new directory
owner and replaces only that record's owner. It never changes the caller's cwd.
Later relative opens, directory actions, executable paths and PATH candidates
use the updated child directory. Failed resolution and allocation release
their node references; failed launches leave PID output untouched.

The protected loader snapshots the resolved file's absolute VFS path before
publishing the child. `alix_get_executable_path` in `unistd.h` returns that
immutable process-owned snapshot, including NUL, with a byte count excluding
NUL. Insufficient capacity reports ERANGE without truncated success; invalid
or read-only destinations report EFAULT. PATH lookup, argv edits and cwd
changes cannot substitute another path. The kernel `runelf` command supplies
the same metadata through the file-backed constructor. Anonymous in-memory ELF
constructors have no file identity and report ENOENT. This is a launch-path
snapshot; subsequent rename does not rewrite it. Run
`make zen-executable-path-qemu-test` for constructor, long-name, relative/PATH,
rename and reply-validation evidence in an eight-CPU guest.

Each user process has a separate 256-entry child registry. It consumes no public
file descriptor. Launch reserves a registry slot before loading/starting a
child, so admission failure cannot start an untrackable process. Its deferred
record owns the reservation, captured context and retained construction watch.
The protected loader reads and validates the real ELF and constructs a fresh
address space/TLS/stack. The child owner exists before thread enqueue; no caller
process pointer, stack or user address is retained by a worker. Parent linkage
uses a PID lookup under the process lock at publication.

The loader pool is separate from storage and network waits. A readiness
executor handles waits without occupying a loader. A completed wait obtains an
owned claim on one quiescent child. Status copies precede the registry removal;
failed copies release the claim without reaping. A caller killed while waiting
abandons its registered request, and claim cleanup also releases ownership.
Concurrent waiters cannot reap the same child twice.

`waitid` uses the same registry and claim protocol. `P_PID` and `P_ALL` with
`WEXITED` report `SIGCHLD`, the child PID/UID, `CLD_EXITED` or `CLD_KILLED`, and
the exit value or terminating signal. `WNOWAIT` releases its claim after copying
without removing the child, so another wait can read or consume the status.
`WNOHANG` clears the complete `siginfo_t` when a child exists but none is ready.
Failed copies and abandoned requests preserve the child. Process groups and
stopped/continued events remain unsupported. Run `make zen-waitid-qemu-test` for
native eight-CPU status, concurrent peek/reap and killed-waiter coverage.

A persistent child monitor holds independent record ownership through terminal
CPU/queue/transition quiescence. At that point it detaches the child's cwd,
files and child registry, permitting pipe EOF before a parent calls `waitpid`.
The retained process/PID and VM backing remain until final reaping. A published
child whose parent exits continues as an orphan. A child created by an
abandoned, unpublished launch is killed and retired after quiescence. No
deferred FD finalizer waits indefinitely for a running child.

The native fixture passes inside eight-CPU Alix:

- Real user-to-user self-launch, copied spaces/UTF-8 argv, cwd isolation,
  CLOEXEC filtering, shared file offsets and independent descriptor flags.
- Pipe EOF with a writer deliberately left open at child exit, before reaping.
- Normal/signal exit encoding, WNOHANG, wait-any, failed-copy rollback and
  eight simultaneous waiters with exactly one successful reap.
- A descendant surviving parent teardown, plus killing an owner observed
  blocked in `waitpid` while its descendant continues writing safely.

`tests/process_child_contract_test.py` executes the production child monitor,
claim and commit code with the real deferred FD primitives. Plain, ASan/UBSan
and TSan pass allocation failure, abandoned claims, copy rollback, unpublished
launch cleanup, orphan survival and 64 concurrent final-owner/monitor races.
The retained kernel-service factory regression also passes ASan/UBSan.

```sh
make zen-process-spawn-qemu-test
make zen-posix-spawn-qemu-test
make zen-spawn-cwd-qemu-test
make zen-nspr-spawn-qemu-test
python3 tests/process_child_contract_test.py
python3 tests/spawn_environment_contract_test.py
python3 tests/process_environment_stack_test.py
```

Native evidence is `build/test-out/process-spawn-qemu.log` and
`build/test-out/posix-spawn-qemu.log`. The latter covers environment visibility
before main, UTF-8/empty/duplicate values, action ordering, self-dup, CLOEXEC,
PATH candidates, signal inheritance/attributes and errors. Environment snapshots
and child-stack encoding also pass host sanitizer tests. The upstream shell now
uses native spawn for its command and Wasm-worker paths, removing its fork/exec
link requirement. A `sh` executable is still required by `os.spawn` and has not
been installed; full shell command compatibility is not claimed.

`spawn-cwd-qemu.log` additionally covers 24 children launched by eight pinned
CPUs, ordered relative opens, owned action paths, absolute/relative executables,
relative PATH lookup, cwd visibility before main and parent isolation through
successful and failed launches. The production cwd action/capture code passes
ASan/UBSan ownership and allocation-failure checks.

NSPR's Alix process backend now uses native posix_spawn. Its helper snapshots
the native environment, merges NSPR_INHERIT_FDS without changing the parent,
and prepares all redirected sources in CLOEXEC temporaries before dup2 actions.
This supports crossed standard descriptors and child-only cwd changes. Like
Unix fork/exec, successful stdio redirection clears nonblocking status on the
shared open descriptions; failed launch restores changed nonblocking bits.
Other status and original CLOEXEC flags remain intact.

The actual helper passes 25 native child launches with eight pinned callers,
stdin/stdout/stderr pipes, crossed descriptors, inherited/explicit/empty
environments, constructor-time state, failure restoration and descriptor leak
checks. An ASan/UBSan host fixture faults every allocation and descriptor
preparation step, including aliased sources. The complete upstream process
source compiles. These are helper/component results; full NSPR initialization,
its wait daemon and the Zen application have not been verified.
