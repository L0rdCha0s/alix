# Timezone & DST Data Strategy

This note captures an end-to-end plan for replacing the hard-coded UTC offsets
(`src/kernel/timekeeping.c:649`) with real IANA timezone definitions.  The
scope covers fetching upstream data, parsing it inside the OS, persisting the
result, and teaching the clock to use the richer transitions so locations like
`Australia/Sydney` report the correct daylight savings offsets.

## Goals

1. **Authoritative data** – consume the official IANA TZDB so we inherit every
   past/future DST rule change without maintaining our own copies.
2. **In-OS refresh** – provide a shell tool that downloads the latest database
   via our TCP/TLS stack (same primitives as `src/sbin/cmd_wget.c`) and stages
   it under `/usr/share/zoneinfo`.
3. **General parser** – support the full TZif (timezone information) format so
   any zone from the database can be loaded without rebuilding the kernel.
4. **Clock integration** – extend `timekeeping_timezone_offset_minutes()` and
   friends to resolve offsets by consulting the parsed transition tables.
5. **Safe fallback** – keep the current static config file so systems without a
   downloaded DB still boot with a sane UTC default.

## Data ingestion plan

### Source

IANA publishes plain-text artifacts alongside the tarballs.  We can avoid
shipping our own gzip/tar implementation initially by fetching:

- `https://data.iana.org/time-zones/tzdb/tzdata.zi` (all Rule/Zone/Link entries).
- `https://data.iana.org/time-zones/tzdb/zone1970.tab` (maps regions → coordinates).

Both are line-oriented text files that `cmd_wget` can download today.

### Downloader (`tzsync`)

1. Add a new sbin command (`src/sbin/cmd_tzsync.c`) that:
   - Accepts optional `--version tzdb2024b` or defaults to `latest`.
   - Downloads `tzdata.zi` and `zone1970.tab` into `/var/cache/tzdb/`.
   - Verifies the HTTP status and basic sanity (non-zero size, header matches
     `# version` line).
   - Copies the files into `/usr/share/zoneinfo/src/` when downloads succeed.
2. Reuse the HTTP helper code from `cmd_wget` by factoring the URL parsing and
   TLS client into a small library under `src/lib/http_fetch.c` so we do not
   duplicate socket/TLS logic.
3. Persist metadata in `/usr/share/zoneinfo/manifest.json` (simple INI-like
   text is fine) noting the tzdb release tag, download timestamp, and checksum.

This step gives us the raw upstream text inside the OS without any gzip/tar
requirement.

## Parsing & compilation

We want to convert the textual `Rule`/`Zone` records into a binary form the
kernel can consume quickly.

### Ingestor layout

Create a userland tool `tzbuild` (lives in `src/sbin/cmd_tzbuild.c`) that takes
`tzdata.zi` as input and emits a compact database file:

```
/usr/share/zoneinfo/alix.tzd
    header: magic="ATZD", version=1, release_id string
    n_zones (u32)
    zone directory entries:
        - name_offset, first_transition_offset, transition_count, property flags
    transition table (sorted UTC seconds).
    ltime blocks storing (utc, offset_minutes, is_dst, abbrev_id)
    abbreviation table (null-terminated strings).
```

Implementation sketch:

1. **Lexer / parser** – implement a small tokenizer that can understand the
   subset of zic syntax we need:
   - `Rule` lines into structs `{name, from_year, to_year, in_month, on_rule,
     at_time, save_minutes, letters}`.
   - `Zone` lines (and continuation lines) to build spans referencing rules or
     fixed offsets.
   - `Link` lines map one zone alias to another entry.
   The grammar is regular enough that a hand-written parser similar to
   `timekeeping_parse_rule_line()` (see `src/kernel/timekeeping.c:261`) will
   work.
2. **Rule resolution** – adapt the existing DST rule helpers in
   `timekeeping.c` (`timekeeping_resolve_rule_day`, `timekeeping_is_dst_active`,
   etc.) so the builder can compute actual transition instants for each span.
   Move these helpers into a shared library (`src/lib/timecalc.c`) so both the
   builder and kernel can use the same math.
3. **Windowing** – we do not need infinite history in-kernel.  During build,
   choose a [start,end] window (e.g. 1970-01-01 .. 2100-12-31) and clip older
   transitions while keeping the last pre-window offset as the base record.
   This keeps the resulting `.tzd` file under a few megabytes.
4. **Serialization** – after computing the transition list for each zone, pack
   everything into the binary structure above.  Use little-endian fields so the
   kernel can `memcpy`+`read32` without byte swapping.
5. **Validation** – add a `--check` flag that recomputes a handful of known
   instants (e.g. 2024-04-07T02:00 Sydney) and prints the offset so we can
   cross-check the output with `zdump` on the host during development.

Running `tzsync && tzbuild` inside the OS yields a single compact database file
plus the zone list for UI use.

## Kernel integration

### Loader

Add a new kernel module `src/kernel/tzdb.c` that knows how to read `alix.tzd`:

1. On boot, `timekeeping_init()` calls `tzdb_load("/usr/share/zoneinfo/alix.tzd")`.
2. The loader:
   - Maps the file via `vfs_data`.
   - Validates the header, release tag, and directory length.
   - Builds a lightweight in-memory view consisting of:
     ```
     typedef struct {
         const char *name;
         const tzdb_transition_t *transitions;
         size_t transition_count;
         int initial_offset_minutes;
     } tzdb_zone_t;
     ```
3. Expose lookup helpers:
   - `const tzdb_zone_t *tzdb_find_zone(const char *name);`
   - `bool tzdb_list_zones(tzdb_enum_cb cb, void *ctx);`

### Timekeeping changes

Refactor `timekeeping.c`:

1. Replace `timekeeping_timezone_state_t` with a structure that either points
   to a tzdb zone or falls back to the legacy fixed-offset data.
2. Update `timekeeping_effective_offset_minutes()` to:
   - If a tzdb zone is active, binary-search its transition array for the
     current UTC seconds (cached pointer + last index for efficiency).
   - Otherwise use the legacy DST math path.
3. Extend `timekeeping_save_timezone_spec()` so when the user picks a timezone
   name, we store both the human-readable string and (if available) the zone
   identifier inside `/etc/timezone/current`.  Proposed file format:
   ```
   [timezone]
   name=Australia/Sydney
   fallback_offset=600
   fallback_dst_enabled=1
   ...
   ```
   This keeps backward compatibility—the kernel reads the zone name first, and
   if loading fails it uses the fallback fields already parsed today.
4. Add a new API `bool timekeeping_select_zone(const char *name);` that looks up
   the zone via `tzdb_find_zone`, updates the active zone pointer, and triggers
   a recalculation of cached DST start/end instants.

### Shell UX

Revamp `src/sbin/cmd_tzset.c`:

1. If `alix.tzd` is present, list real zone names (group by region) instead of
   the hard-coded `UTC±N` options.
2. Support subcommands:
   - `tzset list [filter]`
   - `tzset get`
   - `tzset set <Area/City>`
3. Fall back to the existing static list if the tzdb has not been built yet.

Add a thin wrapper command `tzstatus` that prints:

- Current tzdb release/version.
- Active zone name and offset.
- Next DST transition (computed via the tzdb transition table).

## Connecting to the clock

Once the loader and timekeeping changes land, every place that already calls
`timekeeping_timezone_offset_minutes()` or `timekeeping_local_time()` will see
the corrected offsets automatically:

- Console clock (`src/kernel/console.c` status line).
- Shell prompt time.
- Any apps that call the libc wrapper (`user/libc.c` -> `sys_timekeeping`).

To validate Australia/Sydney specifically:

1. Boot the OS, run `tzsync`, then `tzbuild`.
2. `tzset set Australia/Sydney`.
3. Force the RTC to a known UTC instant (`time set <seconds>` if exposed).
4. Run `tzstatus` and ensure it reports UTC+10 outside DST and UTC+11 during
   the DST window (`2024-10-05` onward).

## Incremental delivery

1. **Phase 1** – land downloader (`tzsync`) and store the raw files.
2. **Phase 2** – implement `tzbuild`, produce `alix.tzd`, and add the kernel
   loader guarded behind a feature flag.
3. **Phase 3** – switch `timekeeping` over to tzdb-backed offsets, keep the
   legacy format as fallback.
4. **Phase 4** – improve UX (listing zones, `tzstatus`, automated cron job to
   refresh monthly).

Each phase is independently testable and keeps the system usable between
checkpoints.

