# Native stdio streams

Native `FILE` objects own an `alix_mutex_t`, access flags and one byte of
pushback. The mutex uses the existing native blocking mutex/futex implementation.
Each stream operation holds it for its complete state and I/O operation;
`fgets` owns the stream for an entire line and `fwrite` for the whole requested
record, including short underlying writes. Private unlocked helpers allow
formatted output to hold the same mutex without recursively locking it.

The application must prevent concurrent use while it closes and destroys a
`FILE`. A stream mutex cannot make a pointer valid after another thread frees
its allocation. Sharing a live stream is supported; sharing another thread's
stack storage as an asynchronous callback argument is not.

`ungetc` provides one byte of pushback, converts it to `unsigned char` and clears
EOF on success. A second push without consumption fails, as does pushing EOF;
neither failure consumes the existing byte. `fread`, `fgetc`, `getc`, `fgets`
and `getchar` consume the pushed byte before another descriptor read. `clearerr`
clears indicators and preserves pushback. These rules follow the
[POSIX ungetc specification](https://man7.org/linux/man-pages/man3/ungetc.3p.html).

For seekable streams, `ftell` and `fgetpos` account for the pending byte without
moving the underlying descriptor. Relative seeks compensate for pushback;
successful positioning clears EOF and pushback. A failed seek preserves them.
`fsetpos` restores the byte position saved by `fgetpos`; wide-stream conversion
state is not implemented. Pushback at offset zero remains readable, but position
queries fail with `EINVAL` until the byte is consumed or positioning succeeds.
The specification leaves that particular position unspecified.

Explicit `fflush(stream)` reconciles pending input to the logical stream
position before discarding its pushback. If the descriptor cannot seek, the
flush fails and preserves the byte. `fflush(NULL)` is an output-only operation
and leaves input pushback alone. Output remains unbuffered, so no unwritten
output data needs flushing. `setbuf` does not currently enable buffering.
The positioning behavior follows the
[POSIX fseek specification](https://man7.org/linux/man-pages/man3/fseek.3p.html).

Reads and writes reject multiplication overflow before performing I/O, return
only complete item counts, and retain partial bytes already transferred. EOF
and error indicators remain separate. `fgets` leaves its destination unchanged
when EOF precedes all input and returns null on a read error. Successful
positioning and `clearerr` permit recovery; `rewind` also clears the error
indicator. Append streams seek to the end before each stdio write while holding
their own mutex. Atomic append across independent streams/processes still
requires a kernel append operation.

`tests/stdio_stream_contract_test.py` executes the production stream code with
seekable/nonseekable mock descriptors, partial I/O and error injection. It tests
pushback, positions, EOF/error recovery, overflow and eight-thread line/record
serialization; it can run under ASan/UBSan or TSan through `HOST_CC`.
`tests/stdio_stream_test.c` is the native fixture, with marker
`STDIO_STREAM_TEST: PASS`. It also creates a per-process fixture file under
`/tmp`; compilation alone does not establish guest execution.

## Wide streams and formatting

`FILE.orientation` starts at zero. `fwide` can select byte or wide orientation
once; the first byte/wide I/O operation also selects it. Seeking and clearing
indicators leave orientation unchanged. Applying the opposite I/O family fails
with `EINVAL` and sets the stream error indicator, including an empty formatted
write. Orientation queries and other successful `fwide` calls preserve errno.

Wide stream functions lock once and use private, synchronous raw-byte helpers.
The C/POSIX encoding is ASCII: byte values or wide characters outside that
encoding fail with `EILSEQ`. One-byte wide pushback therefore shares the same
position/EOF machinery as byte pushback. No UTF-8 conversion is implied.

Memory formatting is different from stream encoding: `swprintf`/`vswprintf`
preserve all native 16-bit units in wide literals and `%ls`, including surrogate
units. Width, precision and `%n` count wide units. `%s` converts ASCII input;
`%lc` preserves a representable native wide unit in memory. Numeric conversions,
including `%Lf`, delegate to Alix's native numeric formatter. This does not
repeat `%n` or string conversions. Insufficient buffer capacity returns a
negative result and terminates the written prefix when capacity is nonzero;
capacity zero is not a sizing API. The buffer path bounds numeric scratch
storage by the prefix that can fit. Stream numeric formatting may fail with
`ENOMEM` if its required workspace cannot be allocated.

Narrow `%ls` and `%lc` use the same ASCII conversion policy. Precision zero
does not inspect the wide string, and `wint_t` is validated before narrowing.
Wide scanning functions are not implemented in this batch.

`tests/wide_stdio_contract_test.py` uses actual production stream and numeric
formatting code with 16-bit units, mock descriptors and host-thread contention.
It covers orientation, encoding failures, Unicode memory preservation, guard
pages, truncation, allocation failures and complete formatted-record locking.
`tests/wide_stdio_test.c` adds real native x87 `%Lf` and eight-thread stream
coverage with marker `WIDE_STDIO_TEST: PASS`; it must execute in Alix to establish
the native acceptance result.
