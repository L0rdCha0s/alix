# Managed timezone activation contract (not implemented)

The staged package is immutable and content-addressed. A future activation
operation should publish a small versioned selection record only after all
package files, metadata and directory entries have been durably flushed.
Publishing requires an atomic native namespace replacement and directory/file
ordering guarantees. Current staging readback does not provide those guarantees.

A reviewable selection record can contain:

```
ALIXTZSEL1
id=iana-2026f-5a6edfe38f4f7000
manifest_sha256=5a6edfe38f4f700080642409cdbc80fa48c557f79ffdcfbfa03857f352371db8
bundle_sha256=ff20c1d6b6de37d395d7f0d28fda5e5e6d7bfa954d2e49e9a195c0d1ec567e4d
generation=<monotonic integer>
previous=<verified prior package ID, or empty>
```

IDs must be validated identifiers under `.alix-releases`, never arbitrary
paths. An unknown/custom selection file must not be replaced. Keep the old
selection and old immutable package until a new selection has passed native
readback and reboot tests. Rollback should atomically republish the verified
prior selection; do not rewrite hundreds of zone files or remove custom data.

The native timezone loader must include package selection in its cache identity.
Currently its default cache is keyed by system configuration generation. An
activation must therefore advance that generation, or introduce a separately
validated package generation. Otherwise a process could retain the old data
after a successful package switch. Readers must receive one coherent selection
and preserve references to any state already in use.

For managed IANA names, read the selected package's `zoneinfo/<id>`. Explicit
absolute `TZ` paths continue to allow deliberate custom files. Define any legacy
root-file fallback explicitly; it must not silently replace an active pinned
package with an older or ambiguous custom file. Preserve all legacy files even
when they are not selected.

The kernel's current ATZD database and clock UI are separate from libc's TZif
reader. System IANA selection must remain coherent across the kernel snapshot,
the native C runtime and ICU. Existing `tzset` shell selection depends on the
ATZD zone catalog; it cannot by itself activate this new TZif package. Implement
the actual selection and kernel clock behavior before claiming production
default-IANA support. No activation record is written by the current installer.
