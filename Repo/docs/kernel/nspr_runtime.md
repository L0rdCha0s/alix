# NSPR library execution in Alix

The complete configured NSPR 4.40 shared library now builds and runs through
public APIs in an eight-CPU Alix guest. This goes beyond the earlier source
audits and extracted-function fixtures. It does not establish a running Gecko
or Zen application.

## Native library contract

`libnspr4.so` is built by Mozilla's real unified NSPR target under
`config/external/nspr/pr`. Alix supplies its canonical C runtime through the
executable's ELF export namespace. The native configuration therefore permits
DSO imports rather than requiring a separate libc shared object. The loader
eagerly resolves imports and rejects missing strong symbols. The fixture also
compares every strong NSPR import against actual executable dynamic exports
before booting.

Native environment snapshot/free declarations have explicit public visibility,
including when consumed under Mozilla's hidden-visibility pragma. The Alix
`PR_DuplicateEnvironment` backend uses the owned libc snapshot instead of an
unsynchronized foreign `environ` array. The NSPR allocation and free APIs use
the same native allocator.

NSPR's real compiler-generated stack checks import the process-wide guard and
failure handler. The test executable links the optional native SSP archive,
whose entropy initialization precedes ordinary user callbacks. Protected shared
library constructor, eight-CPU call and deliberate-corruption checks have
separate acceptance in [stack protection](stack_protector.md).

## Verified public API paths

`make zen-nspr-runtime-qemu-test` builds the library and a consumer using actual
configured public headers. The consumer loads it with native `dlopen` and calls
its exports, including its normal error APIs. The suite passes:

- Initialization, version 4.40, native CPU count and environment duplication.
- Eight native NSPR threads, 512 mutex-protected updates, condition-variable
  notification, one shared once initializer and eight TLS destructors.
- Pipe write/read and polling, plus pollable-event creation, signaling,
  waiting and destruction.
- A real TCP connection to the fixture server, `PR_Writev`, and echo receive.
  NSPR's pipe method table supports ordinary writes; its gather-write method is
  exercised on the TCP descriptor.
- File creation/sizing, shared file mappings, synchronization, unmapping and
  readback through the full NSPR APIs.
- `PR_CreateProcess` and `PR_WaitProcess`, using the actual wait daemon. The
  spawned native child inherits the environment, independently loads and
  initializes NSPR, cleans it up, and returns status 37 to its parent.
- NSPR cleanup and successful retirement of the parent process.

The core NSPR library is kept resident with `RTLD_NODELETE`, matching a
process-lifetime runtime. This test does not establish arbitrary unloading of
NSPR while TLS callbacks or system threads remain live.

`build/test-out/nspr-runtime-qemu.log` contains the parent/child markers and
process retirement records. `nspr-runtime-network.pcap` records its real TCP
exchange. Its boot-image sidecar identifies the tested kernel and executable.

## Current limits and reproduction

Server sockets, local socket pairs, datagrams, descriptor passing and complete
half-close behavior still need kernel backends. Their C entry points report
unsupported operations rather than successful substitutes. Connected address-free
`sendto`/`recvfrom` use the implemented TCP paths. The independent socket guest
checks these error paths, unchanged output and connected forwarding.
File-mapping EOF/truncate restrictions remain documented in
[file mappings](file_mappings.md). Full application startup, NSS and the Zen UI
remain further integration gates.

```sh
make zen-gecko-configure
make zen-nspr-library-build
make zen-nspr-runtime-qemu-test
make zen-writev-qemu-test
make zen-ssp-loader-qemu-test
```

Dedicated NSPR builds always refresh
`build/ports/zen/nspr-full-library-build.log`, streaming the build output and
recording its start time, command and exit status. Runtime-test output and serial
evidence remain separate. Full Gecko builds are recorded in `gecko-build.log`.
