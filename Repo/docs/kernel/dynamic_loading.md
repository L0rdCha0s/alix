# Native ELF dynamic loading

The user runtime implements dlopen, dlsym, dlclose, dlerror and dladdr in
`user/lib/dlfcn.c`. Libraries are real x86-64 ET_DYN files loaded into owned VM reservations.
Compatible read-only segments use shared native file mappings, whose physical
cache pages and PTEs populate on first access. Writable segments use private
file snapshots, with explicit BSS zeroing; incompatible boundary pages retain
the anonymous-copy path. Read-only code is shared across browser processes. Code runs inside Alix; there
is no host dynamic linker or secondary libc instance.

The upstream compiler driver builds shared objects with PIC, global-dynamic
TLS, native DSO finalization identity, dynamic symbol hashes, eager relocation,
RELRO and non-executable stack metadata. Its executable path stays fixed
ET_EXEC and exports standard ELF symbol metadata from the linked program.
Executables using dlopen must provide those exports; the driver adds
`--export-dynamic --no-dynamic-linker` and the native linker script retains
the tables in the existing load segments.

The native CRT resolves main-module initial-exec TLS offsets and defined
`R_X86_64_GLOB_DAT` GOT imports before user constructors and SSP initialization.
Function/data imports must refer to the executable's own image or an absolute
symbol; unresolved weak imports resolve to NULL. Undefined strong imports,
indirect functions, nonzero GOT addends and writes outside writable data are
rejected. It uses the kernel's variant-II TCB: FS:0 is the thread pointer,
and FS:8 is the static TLS block base. The exported main-image TLS size and
TLS addends are checked before writing each offset. This also preserves native math code's
per-thread signgam state when the executable exports dynamic symbols.

Libraries can import real program functions/data and resolve DT_NEEDED
dependencies. The complete dependency graph is mapped before relocation;
constructors run afterward in dependency order, including cyclic graphs.
Relocation providers are retained even when the relationship comes from a
global symbol binding rather than a DT_NEEDED entry. Global/local scopes,
NOLOAD, NODELETE, executable handles and address lookup are implemented.
Library lookup supports canonical paths, an owned LD_LIBRARY_PATH snapshot,
RUNPATH/RPATH with ORIGIN expansion, and `/usr/lib:/lib` defaults.

The loader accepts SysV and GNU symbol hashes, ordinary x86-64 RELA and packed
RELR relative relocations. Both binding modes resolve imports eagerly. Load
segments initially receive writable non-executable backing; after relocation,
the loader applies their final permissions and GNU RELRO. Writable executable
load combinations, text relocations, malformed ranges and unsupported relocation
formats fail before constructors. Temporary image FDs use CLOEXEC and bounded
pread loops so a concurrent spawn cannot inherit an image descriptor.

Global-dynamic/local-dynamic TLS is allocated lazily per thread, using the
module's initialized template, zero fill and alignment skew. Module IDs are
never reused. Thread-local blocks retain the image through cleanup. The native
C++ thread-destructor registry also pins the module identified by its DSO
handle, so a destructor cannot outlive its executable code. Destructor pins are
released after callbacks return. Normal close finalizes unused modules in
reverse initialization order; collection follows both dependency and binding
edges. An unmap that cannot reserve kernel retirement metadata retains hidden
ownership and is retried by a later collection.

Process exit finalizes resident images, including NODELETE and TLS-pinned
libraries. It keeps their code mapped through remaining exit handlers and
process-wide thread termination. The kernel then reclaims the address space.
Registry changes and first TLS allocation use a recursive loader gate. Existing
TLS blocks use a per-thread fast path: the block pins its module until thread
cleanup, so ordinary TLS access needs no global loader lock. Error state and
TLS block ownership are per thread. No caller stack or user process pointer is retained
by another worker.

Native executable startup now uses the existing loader for DT_NEEDED libraries.
The CRT first resolves its own GOT/TLS and initializes SSP, then maps and eagerly
relocates the complete dependency graph. Ordinary executable preinit callbacks
run next, dependency constructors run in dependency order, and the CRT then runs
its main constructor array and `main`. Executable TLS keeps its kernel-owned
static block; DSOs retain the existing dynamic TLS path. Startup libraries remain
owned by the executable dependency graph, and their finalizers run after later
main-program exit registrations. Load failure reports a native loader error and
exits before `main`. The fixed executable keeps its kernel-established segment
permissions. DSOs still receive final permissions and RELRO after relocation.

The native driver supplies a literal `$ORIGIN` executable RPATH so a relocated
browser bundle can find both direct and transitive startup libraries beside its
launcher. RUNPATH remains local to its requesting object. The ELF validator
requires the defined startup loader and ABI version 1 for executable dynamic
imports, and checks all relocation tables, symbol versions and writable targets.
It also accepts disjoint RELA/JMPREL tables sharing one SHT_RELA section, while
rejecting uncovered or overlapping table ranges. The actual Zen updater now
links through these checks and loads its startup libraries in Alix QEMU. It
initializes NSS and reaches its normal usage message; see
`build/ports/zen/zen-launch-2/serial.log`. Applying an update remains unverified.

Current limits are explicit. Initial-exec TLS defined by loaded DSOs,
GNU indirect functions and GNU unique-symbol semantics are not established.
Unsupported TLS/relocation forms and malformed version tables return a loader error. This is native
ELF support for the port, not a Linux binary compatibility layer. The full
[NSPR library](nspr_runtime.md) runs, while Zen startup remains unverified.

`make zen-dynamic-loader-qemu-test` builds and runs native C/C++ shared objects
in five private eight-CPU QEMU guests. Evidence includes libc imports and shared
allocator state, dependencies, GNU hashes/packed relocations, 512 isolated TLS
updates, constructor/finalizer order, global/local binding retention, defined
NULL symbols, error state, unload and NODELETE. Eight pending C++ destructors
keep code alive after dlclose; a separate process-exit case finalizes with live
threads while retaining code. Hardware write attempts against RELRO and text
produce their intended user faults and return to the shell.

The host ASan/UBSan contract executes production loading/relocation/collection
code with faultable allocation, file I/O and VM preparation, plus 3,000 metadata
mutations. Target instructions are not executed in that host model. Native VM
and actual target-code execution are proved by the guests. The existing LLVM
libc++/libc++abi eight-CPU thread/TLS/file/exit regression also passes.

`tests/dynamic_loader_startup_contract_test.py` executes the production startup
fixups under ASan/UBSan with function, TLS, weak and defined-NULL imports and 18
malformed-metadata cases. The real configured FreeType executable supplies
native `GLOB_DAT` execution evidence, including its function pointers, longjmp
and SSP guard. The upstream ELF validator accepts that executable and rejects
corrupted GOT symbols/addends, in addition to its existing TLS corruption tests.

## Symbol versions

The native loader now parses VERSYM, VERDEF and VERNEED, including inherited
definition names, default/nondefault aliases and weak requirement metadata.
Indices, flags, chains, auxiliary counts, name/hash consistency and readable
load bounds are validated before constructors. Required names/hashes must exist
in the declared dependency; a missing nonweak requirement fails loading.
Relocations match the requested version, while ordinary dlsym skips nondefault
aliases. `dlvsym(handle,name,version)` performs explicit lookup. Versioned data
and dynamic TLS use the same rules. Runtime/build-validator checks share these
limits; tables are not ignored to make a library load.

`make zen-version-loader-qemu-test` verifies default and legacy function/data
aliases, actual versioned consumer relocations, missing-version rejection before
constructors, 1024 TLS updates on eight CPUs and unload after thread cleanup.
`tests/version_metadata_contract_test.py` runs both current parsers against 34
corruptions and faultable allocation, then checks threaded lookup/TLS under
ASan/UBSan and TSan. Target instructions run only in the native guest.

Gecko's actual versioned libmozsqlite3.so now passes validation and native
loading, including FTS5/vector extensions and two-boot WAL/concurrency readback.
Upstream executables retain the canonical initialized SSP runtime even when
their own objects are uninstrumented, so protected DSOs can resolve it.
