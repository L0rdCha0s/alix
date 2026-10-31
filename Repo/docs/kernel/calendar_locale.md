# Calendar, timezone and C/POSIX locale

`user/lib/calendar.c` provides signed Gregorian `gmtime_r`, `gmtime`, normalized
`timegm`, `asctime_r` and `asctime`. Conversion handles negative epoch values,
century leap rules and the 2038 boundary with bounded arithmetic. Dates whose
year cannot fit `struct tm.tm_year` fail with `EOVERFLOW`; failure preserves the
caller's output. A valid epoch of -1 is distinguished from failure by unchanged
`errno`. The non-reentrant interfaces use native ELF thread-local storage.
`struct tm` includes `tm_gmtoff` (seconds east of UTC) and a stable `tm_zone`
designation; UTC conversions set them to zero and `UTC`.

`asctime_r` writes exactly 26 bytes including newline and NUL for valid fields
and years 0 through 9999, padding shorter years to four columns. Invalid fields
fail with `EINVAL`; negative or larger years fail with `EOVERFLOW`, without
writing the output buffer. The caller must supply at least 26 bytes.

`user/lib/locale.c` installs the C locale and its equivalent POSIX alias. Query
operations return `C`. A request for an empty locale name resolves nonempty
`LC_ALL`, then the category variable, then `LANG`, defaulting to C when none is
set. `LC_ALL` validates every category before success. Unsupported names,
including `C.UTF-8` and `en_US.UTF-8`, return NULL and preserve the current locale.
`localeconv` provides actual C numeric/monetary values. It does not claim that
additional encodings, collation data or translated message catalogs exist.
ICU's independent Unicode and locale data remain enabled in the upstream build.

`user/lib/timezone.c` provides `tzset`, `localtime[_r]`, `mktime`, `ctime[_r]`
and the `timezone`, `daylight`, `tzname` variables. An unset `TZ` uses the
versioned `sys_timezone_info` snapshot, preserving the configured UTC, fixed
offset, monthly-rule or IANA selection. Numeric offsets in the wire are seconds
east of UTC; the POSIX `timezone` global uses seconds west. Native manual
configurations without abbreviations receive numeric designations such as
`UTC+10:00:00`, not invented regional abbreviations.

Explicit `TZ` accepts POSIX standard/DST offsets, `Jn`, day-number and
month/week/weekday rules, signed transition times, and wall/standard/UTC clock
bases. Omitted DST rules use the documented Alix default
`M3.2.0/2,M11.1.0/2`. An empty `TZ`, `UTC` or `GMT` selects UTC. Named zones load
`/usr/share/zoneinfo/<zone-id>`; a leading colon also permits an explicit file
path. No IANA zone is synthesized from its name or today's offset.

The loader validates TZif versions 1–4, count/length/index bounds, transition
order, offsets, names and rule footers. Native clocks use POSIX seconds, so
leap-aware `right/` files return `ENOTSUP`. Missing/corrupt files fail conversion
instead of reporting a successful UTC fallback. A transition table without a
nonempty footer leaves dates on or after its final transition unspecified under
RFC 9636; this implementation reports `EOVERFLOW` there. A zero-transition file
without a footer uses type zero for all representable dates. File size is
limited to 1 MiB and a designation to 255 bytes.

Loaded timezone states are immutable and reference counted. A new state is
validated before publication; old readers retain their state until completion.
An older system generation cannot replace a newer cached generation. Parse and
load failure frees temporary allocations; only validated, referenced names are
interned for process lifetime so returned `tm_zone` and `tzname` strings remain
valid after state changes. `tzset` reloads files and reports failures through
`errno` despite its void return type. Callers must serialize mutation of the
process environment with environment readers, as the existing Alix environment
implementation does not provide that synchronization.

`mktime` normalizes calendar fields and checks candidate offsets through actual
timestamp conversion. Explicit DST hints select the corresponding occurrence
in a fold. Without a hint, a fold selects the earlier UTC occurrence and a gap
normalizes forward using the offset before the transition. Historical offsets
that were not active near the date cannot partly fill a DST gap.

`user/lib/calendar_format.c` implements C/POSIX `strftime` conversions using
the installed C locale, including ISO week-years and bounded composite formats.
`%z` formats the date's `tm_gmtoff` as HHMM; historical offset seconds remain
available in the field. `%Z` uses its actual designation. C-locale `E`/`O`
modifiers use the ordinary forms. Unsupported directives return zero with
`EINVAL`; insufficient output space returns zero and clears the first byte.

The old `SYSCALL_TIME_INFO` ABI remains available for the clock UI. It reports
only the current offset/display name. ATZD v1 stores minute offsets, omits
abbreviations and has a finite expansion range; the new libc does not use it as
a substitute for full TZif calendar data. Production Alix still needs a pinned,
reproducible IANA TZif package. The native fixture's three embedded zones do not
constitute that deployment. ICU's native default-zone integration must also
consume the actual system zone identity/rules instead of assuming that every
abbreviation identifies an IANA zone.

`python3 tests/calendar_locale_contract_test.py` runs the production modules
with host ABI headers under ASan/UBSan. It compares 50,000 signed UTC conversions
and 50,000 normalized inputs against host libc, checks extrema/output/errno
contracts, and verifies eight-thread buffer isolation and locale resolution.
Darwin's timegm rejects pre-1900 input; negative-era cases therefore compare
host gmtime results and verify the native inverse. This is host evidence.

`make calendar-locale-qemu-test` runs `tests/calendar_locale_test.c` through
`run-via-agent.sh`. The native fixture passed in Alix with
`CALENDAR_LOCALE_TEST: PASS workers=8 cpu_mask=0xFF utc=1 locale=1 wall=1 snapshot=1`.
It exercises the real headers, errno, locale environment and thread-local storage
across eight CPUs, plus millisecond wall-time conversion and timezone snapshot
layout, contents and error returns. Serial evidence is retained in
`build/test-out/calendar-locale-qemu.log`.

`python3 tests/timezone_contract_test.py` executes the production timezone and
formatting modules under ASan/UBSan, comparing eleven POSIX/named zones with
host libc. It additionally checks explicit rules, gaps/folds, historical offset
seconds, future footer rules, malformed files, leap-file rejection, interrupted
reads, allocation failures, repeated reloads, reference-count saturation and
eight readers across 6,000 concurrent system-configuration generations. Where
Darwin's POSIX-rule history or strftime offset behavior differs, the suite uses
explicit rule expectations or the independently verified timestamp offset.

[`tests/fixtures/timezone/README.md`](../../tests/fixtures/timezone/README.md)
documents the exact TZif bytes and independent reference cases for
`tests/timezone_test.c`. The native fixture writes those bytes through Alix's
actual file APIs and tests their loader, seasonal transitions, formats and
eight-CPU readers. Its required marker begins
`TIMEZONE_TEST: PASS workers=8 cpu_mask=0xFF tzif_samples=63`.
The native fixture passed in an eight-CPU Alix guest with
`TIMEZONE_TEST: PASS workers=8 cpu_mask=0xFF tzif_samples=63 posix=1 fold=1 gap=1 format=1`.
Evidence is retained in `build/test-out/timezone-qemu.log`. This verifies the
real file loader and embedded regression zones; production IANA deployment is
still a separate requirement.

The C locale contracts follow [C11 draft N1570, section 7.11](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf).
Full timezone data should follow the [TZif specification, RFC 9636](https://www.rfc-editor.org/rfc/rfc9636.html).
