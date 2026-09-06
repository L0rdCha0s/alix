# Audio streaming and playback diagnostics

## Playback path

`atk_mp3` reads compressed input through `user/lib/mp3_stream.h`, decodes with
minimp3, resamples to 48 kHz stereo, and writes signed 16-bit little-endian PCM
to `/dev/audio`. Each stereo frame is four bytes. The HDA write interface rejects
partial frames and unaligned offsets; it blocks when its bounded queue is full.

The ATK application runs decoding and audio writes in a dedicated worker. Its UI
and player state live in heap memory shared with that worker. Pause, seek and
close stop and join the worker before changing decoder state or releasing its
buffers. A successful write means PCM has been queued, not that it has reached
the speakers. Already-queued audio drains during control transitions.

`src/drivers/hda.c` maintains a 256 KiB DMA ring, with at most 64 KiB queued ahead
of the controller: about 341 ms of 48 kHz stereo PCM. Startup waits for 16 KiB or
a 20 ms timeout, so short sound effects still start. A housekeeping thread reads
LPIB and clears consumed ring memory. After an empty queue, the driver keeps RUN
set and inserts an 8192-byte silent lead before new PCM, with a 5 ms fade-in.
The lead provides about 42.7 ms of separation from the sampled DMA cursor; it is
a recovery mechanism and should not recur during uninterrupted playback.
Volume changes ramp over 240 frames (5 ms).

One process owns queued audio at a time. Another process's write fails while
that owner's queue is occupied; a drained queue may change owners. This is
serialization, not a software mixer. The queue bound and backend buffering also
bound how promptly previously submitted audio can stop after a pause or seek.

## Why the earlier playback skipped

The previous MP3 loop refilled its 32 KiB compressed buffer only after decoding
the remaining bytes. When a MPEG frame crossed that boundary, minimp3 saw an
incomplete frame, discarded synchronization data and reset its bit reservoir.
Refilling afterward could not recover the lost frame or its dependent frames.
The shared input adapter now preserves unread bytes and refills before decode,
including the lookahead needed for frame synchronization. Successful short
reads are not treated as EOF.

The old ATK loop also performed blocking PCM writes on the UI thread. Drawing,
event handling and production of audio therefore competed on the same loop.
The worker separates audio production from UI scheduling; the larger bounded
driver queue provides additional scheduling margin.

There was also an independent QEMU drop path. The tested QEMU 10.1.2 codec has
an 8192-byte private timer buffer. If it fills before its output callback runs,
QEMU discards the whole buffer even though guest LPIB has already advanced.
This does not appear as a guest HDA stream error. The Makefile therefore selects
`hda-output,use-timer=off`, which paces DMA from output callbacks on this version.
An explicit `HDA_MODEL=hda-output,use-timer=on` override remains useful for
comparison. See the [QEMU codec implementation](https://github.com/qemu/qemu/blob/v10.1.2/hw/audio/hda-codec.c#L336)
and [LPIB update after DMA](https://github.com/qemu/qemu/blob/v10.1.2/hw/audio/intel-hda.c#L420).

An eight-core TCG/CoreAudio baseline using a generated 20-second, 997 Hz,
44.1 kHz stereo, 128 kbps MP3 captured only 19.295 seconds of active audio, with
84 ms of interior silence and a longest silent interval of 13 ms. The decoder
reproduction independently accounted for 27 lost MPEG frames, about 705 ms.
The same guest snapshot with `use-timer=off` preserved those decoder defects but
removed the QEMU codec overrun and timer adjustments. The timer-enabled run
recorded one overrun and 122 adjustments; the callback-paced run recorded zero
of each. These are separate defects, requiring both fixes.

With the decoder, worker and driver fixes, the same real guest playback captured
20.001 seconds of active audio with no interior silence and no QEMU codec
overruns. It contained 19,942 tone cycles (19,940 expected); the maximum sine
recurrence residual fell from 174 to 16 PCM units. Separate captures verified
sound after restart, resume and a seek to 71%, silence after pause/close, and a
clean application exit. The trace still observed occasional delayed host audio
timers; those did not cause missing PCM in the continuous recording.
The final `make audio-qemu-playback-test` run exited successfully. Its result and
screenshots are under `build/test-out/audio-playback/`. After the control checks,
the visible proc counters showed no queued bytes, three empty transitions, two
reprimes, zero stream errors and zero rejected writers. Those transitions
include intentional EOF, restart and pause/resume; they are not three playback
failures.

## Runtime counters

The following read-only numeric files are exposed under `/proc/sys/audio/`:

| File | Meaning |
| --- | --- |
| `queued_bytes` | PCM still queued ahead of the last observed DMA cursor |
| `empty_events` | Transitions from occupied to empty; includes normal EOF |
| `reprime_events` | Writes resumed after an empty running stream |
| `stream_errors` | Observed HDA FIFO/descriptor errors |
| `rejected_writers` | Attempts by another process while an owner has queued PCM |
| `writer_pid` | Most recently accepted producer process |
| `running` | Whether the driver considers DMA running |

`/proc/sys/audio/volume` remains the writable volume percentage. Counters are
snapshots; an empty event at EOF is expected, and a reprime after an intentional
pause is expected. Repeated reprimes during uninterrupted playback indicate
producer starvation. Zero stream errors do not rule out a QEMU codec drop.

## Reproducing and verifying playback

Run the host regression suite and a real guest capture:

```sh
make
make audio-stream-contract-test
python3 tests/audio_qemu_playback_test.py --label fixed --expect-clean --exercise-controls
```

The runtime diagnostic requires QEMU, ffmpeg, and the existing populated
`data.img`. It boots exclusively through `run-via-agent.sh`, uses eight-core TCG,
copies writable firmware/data, and supplies a private boot volume. The kernel
and player are snapshotted before boot; the exact player and generated tone are
downloaded into the guest over a loopback HTTP server. Original guest disks and
firmware are not modified. `--no-build` reuses current build artifacts.

Results are written under `build/test-out/audio-<label>/`: kernel/player hashes,
QEMU version, a captured WAV, trace events, serial log, and screenshots. The
continuous-tone checks reject codec overruns, interior silent intervals over
5 ms, shortened playback, missing tone cycles, and a sine recurrence residual
above 50 PCM units (a check for abrupt waveform discontinuities).
`--exercise-controls` then
records separate clips for restart, pause, resume, seek and close, checking
that sound returns or stops as appropriate and that the application exits
without a kernel failure. A final terminal screenshot shows the audio counters.

For the timer comparison, run the same snapshot separately with
`--use-timer on` and `--use-timer off`; do not run competing QEMU instances during
timing measurements. `--backend wav` is available for a backend comparison,
but control-phase captures require `coreaudio` or `none`.

The capture is taken from QEMU's mixer. It verifies decoded PCM continuity and
the controller/codec path, including the codec's internal drop behavior. It
does not record the physical Mac output device or establish an audible listening
test. The desktop automation assumes the supplied firmware's 1280x1024 desktop;
inspect `player-ready.png` and use `--input-x`/`--input-y` if that layout changes.
