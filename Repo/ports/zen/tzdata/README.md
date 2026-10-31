# Pinned native IANA timezone package

This builds the complete ordinary, leap-free TZif package from official IANA
`tzcode2026f` and `tzdata2026f`, using the matching upstream host `zic`.
IANA listed 2026f as current on 2026-10-31; its
[release notes](https://www.iana.org/time-zones/releases) include Cuba's canceled
2026-11-01 fallback. Existing parser fixtures remain pinned separately to 2026e.

`upstream.json` pins the exact official HTTPS archive URLs, sizes and SHA-256
hashes. The hashes were computed from those downloads; detached PGP signature
verification is not claimed. Missing archives fail unless `--fetch` is given.
Wrong hashes, unexpected source entries and modified source files stop the
operation without overwriting them. The upstream LICENSE is packaged.

```sh
python3 ports/zen/tzdata/build.py --fetch
python3 ports/zen/tzdata/test_build.py
```

All source, host objects and packages stay under
`ports/zen/upstream/tzdata-2026f`, outside QEMU's FAT-backed `build/`. The builder
uses the official main data and backward aliases with `zic -b fat`, without
leap data or a time-range cutoff. Every result must be TZif v2 or later with a
nonempty future-rule footer and must load with Python's independent `zoneinfo`
reader. Alias bytes must equal their source targets; aliases become ordinary
files because native Alix does not provide hard links to userspace.

The host build preserves the pinned `version` file while rebuilding `zic` and
`tzdata.zi`. Otherwise upstream's Git version rule can accidentally describe
the enclosing Alix repository and produce a misleading `2026f-dirty` build.

The current reproducible artifact is:

| Property | Value |
| --- | --- |
| Package ID | `iana-2026f-5a6edfe38f4f7000` |
| Zone/alias files | 598, including 253 aliases |
| Total files | 606, including source metadata, license and manifest |
| Bundle size | 996,648 bytes |
| Bundle SHA-256 | `ff20c1d6b6de37d395d7f0d28fda5e5e6d7bfa954d2e49e9a195c0d1ec567e4d` |
| Manifest SHA-256 | `5a6edfe38f4f700080642409cdbc80fa48c557f79ffdcfbfa03857f352371db8` |

The builder prints a receipt naming the bundle, manifest directory and generated
installer configuration. With the current pin, build and check the native tools:

```sh
python3 ports/zen/tzdata/build_installer.py \
  ports/zen/upstream/tzdata-2026f/packages/iana-2026f-5a6edfe38f4f7000.json
python3 ports/zen/tzdata/test_install.py \
  ports/zen/upstream/tzdata-2026f/packages/iana-2026f-5a6edfe38f4f7000.json
python3 ports/zen/tzdata/test_catalog.py \
  ports/zen/upstream/tzdata-2026f/packages/iana-2026f-5a6edfe38f4f7000.json
```

`build_installer.py` consumes `ALIX_RUNTIME_OBJECTS`, or the existing native
toolchain's runtime-object manifest. It must run after the normal Alix build
has finished. It compiles the native C installer and the existing Alix SHA-256
implementation, links static x86-64 ELF executables against Alix's CRT/libc,
and rejects unresolved symbols or non-native runtime objects. No host library
is linked into a guest executable.

## Native staging contract

`tzdata_install.elf check|stage|verify <bundle>` accepts only the bundle hash
compiled into that installer. It validates all entry names, lengths, ordering
and SHA-256 hashes before touching the destination. It stages beneath:

```
/usr/share/zoneinfo/.alix-releases/iana-2026f-5a6edfe38f4f7000/
```

The installer uses the documented physical `/root/usr` mount and checks each
subsequent directory component's native type, rejecting symlink redirection.
It first audits every destination. Identical files are retained; a mismatched
file, non-file leaf or unusable directory aborts before writes. Missing files
are created and immediately read back, then the complete package is read back
again. Running the same stage twice is idempotent. Extra custom files are
preserved. Existing `/usr/share/zoneinfo/src`, `alix.tzd`, root-level custom
zones and `/etc/timezone/current` are not package destinations.

The versioned staging namespace requires one writer. Native `O_EXCL`, rename
and fsync are not yet available, so this utility does not claim concurrent-write
exclusion, atomic publication or crash durability. A partial or mismatched
stage remains inactive and is not overwritten automatically. Previously active
data is unaffected because staging does not activate a release or change system
configuration. Removal of inactive stages and atomic selection/rollback should
use the forthcoming native filesystem primitives, not unchecked shell deletion.
See [the activation contract](activation.md) for the remaining integration.

The custom bundle format is little-endian: `ALIXTZP1`, u32 schema 1, u32 entry
count; each entry contains u32 ASCII path length, u32 data length, 32-byte
SHA-256, path bytes and unchanged file bytes. Paths are sorted and unique.
This format lets the native installer enforce integrity and preservation;
Alix's current `unzip` directly truncates existing destinations.

## Disposable guest verification

```sh
python3 ports/zen/tzdata/guest_test.py \
  ports/zen/upstream/tzdata-2026f/packages/iana-2026f-5a6edfe38f4f7000.json \
  --timeout 120
```

The harness uses `run-via-agent.sh`, a fresh sparse data image and copied UEFI
variables. It never points QEMU at the user's persistent data image. One native
acceptance ELF contains the exact package, writes its bundle through Alix file
IO, preflights, stages twice, verifies all file hashes and runs the calendar
verifier. It also checks custom-file sentinels and the unchanged native system
timezone snapshot.

The verifier loads all 598 installed names through absolute versioned paths and
checks four independent Python `zoneinfo` reference cases per name: 2026-11-01,
2027 summer, 2038 and 2200. These include the new Cuba/Manitoba behavior. The
`Factory` unspecified zone must fail honestly; it is counted separately.
Require all of these markers, a normal shell return and no kernel failure:

```
TZDATA_CHECK: PASS
TZDATA_STAGE: PASS
TZDATA_VERIFY: PASS
TZDATA_RUNTIME: PASS release=2026f zones=598 cases=2392 aliases=253 unknown=4 inactive=1
TZDATA_PACKAGE_TEST: PASS release=2026f files=606 config_preserved=1 custom_preserved=1 inactive=1
```

Host ASan/UBSan tests passed full-package staging, idempotence, byte corruption,
conflicts, symlink rejection, custom-file preservation and interrupted writes.
All 2,392 calendar cases also passed against the production calendar/TZif code
under host sanitizers. Both standalone tools and the combined guest fixture
link as native ELF. Full-package guest execution remains a separate acceptance
gate; its log belongs at `build/test-out/tzdata-package-qemu.log`.

## ICU integration still required

ICU `putil.cpp::uprv_tzname()` needs an explicit Alix branch for an unset process
`TZ`: query the real system configuration and return `zone_id` for IANA kind.
`TimeZone::detectHostTimeZone()` already passes that identity to
`createSystemTimeZone()`. The kernel display label and `tzname` abbreviations
are not reliable IANA identifiers. Fixed and manual-rule settings need accurate
ICU zone construction, not a named-region guess.

Firefox 159's `intl/tzdata/VERSION` and updated resource source are **2026e**;
the base ICU resource is 2026a. The native 2026f package does not update ICU's
independent rules. A pinned ICU timezone-resource update is required before
claiming that JavaScript Intl uses 2026f. Installing the package, activating the
system selection, and integrating the browser's own data remain distinct gates.
