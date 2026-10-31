# Native timezone acceptance data

These are exact leap-free TZif files read from the installed macOS timezone
database `2026e.1.0`, whose `+VERSION` is `2026e` and whose `tzdata.zi` identifies
`2026e-rearguard`. `manifest.json` records the resolved source paths, lengths and
SHA-256 hashes. The underlying IANA tzdata input identifies itself as public
domain. They are fixed test inputs, not the production Alix timezone package.

`python3 tests/generate_timezone_fixtures.py` verifies those hashes and encodes
the unchanged bytes into `tests/timezone_fixtures.h`. It derives 63 calendar and
formatting reference cases using Python's independent `zoneinfo` reader on
these exact files. Cases cover historical offset seconds, the ICU 2007 seasonal
probes, southern DST and Lord Howe's half-hour change, New York's spring gap and
autumn fold, ISO week-year boundaries, 2038 and year-2200 footer rules.

`tests/timezone_test.c` writes the embedded original bytes to `/tmp` inside a
disposable Alix guest, then loads them through the real libc/native file path.
It compares the results with the independent reference records and repeats
New York conversions on eight CPUs. The fixture also uses the native system-UTC
configuration syscall and explicit POSIX TZ rules. Its required marker starts
`TIMEZONE_TEST: PASS workers=8 cpu_mask=0xFF tzif_samples=63`.

A production installation still needs an explicitly pinned, reproducible IANA
TZif package and its zone-ID deployment. Passing these three embedded test
zones does not establish that every configured IANA zone is installed.
