# User signal registration and synchronous raising

Alix provides the C `signal` and `raise` interfaces for `SIGABRT`, `SIGFPE`,
`SIGILL`, `SIGINT`, `SIGSEGV` and `SIGTERM`. Dispositions belong to the process;
an atomic exchange installs a handler and returns the previous disposition.
`SIG_ERR` is rejected as an installation value. Unsupported numbers return an
error with `errno = EINVAL`.

`raise` captures the current disposition atomically and delivers the signal on
the calling thread. `SIG_IGN` returns successfully, and an installed callback
receives the signal number. Handlers remain installed after returning, including
across repeated and nested raises. A concurrent registration may affect the
next raise; no registry lock is held while application code executes. There are
no shared stack records or allocated callback messages.

The default action terminates the whole process through the raw exit syscall,
using status `128 + signal number`. It does not run `atexit` callbacks.
`abort()` first raises `SIGABRT`; if the disposition ignores the signal or its
handler returns, `abort()` still terminates with status 134.

ICU's decimal code includes `signal.h`, which exposed this missing interface
during the actual build. Its pinned source already compiles out the nearby
`raise(SIGFPE)` call under `#if 0`; the port leaves that upstream choice intact.
The implemented signal APIs are exercised by native callers and tests. They do
not provide kernel-generated hardware or asynchronous signal delivery.
In particular, registering a `SIGSEGV` callback does not yet redirect a CPU page
fault into that callback. There are no successful placeholder implementations
of `sigaction`, signal masks, `sigaltstack`, `siginfo_t`, user fault contexts or
signal-return machinery. SpiderMonkey's Wasm fault/trap backend requires those
native facilities before it can run; the synchronous C interfaces do not meet
that separate requirement.

`tests/signal_contract_test.py` exercises production registration, dispatch and
abort logic with host exit models and concurrent callers.
`build/user/signal_test.elf` checks 2,048 callbacks on their actual calling
threads, persistent/nested handlers and invalid requests in Alix. Its
`default-fpe`, `abort-handler` and `abort-ignored` modes must terminate with
statuses 136, 134 and 134 respectively. These deliberate termination modes must
be checked by a guest harness that also verifies shell recovery.

All four modes passed through `tests/signal_qemu_test.py` in isolated native
eight-CPU Alix guests; logs are `build/test-out/signal-*-qemu.log`. The harness
rejects unexpected CPU/kernel faults, checks the expected markers and requires
shell return. Numeric exit status is verified by the host production-code
contract, since the current shell discards child exit status.

These results verify synchronous delivery, not hardware or asynchronous signals.
