# Synthetic audio fixtures

These MP3 files contain 2.4 seconds of generated stereo sine waves (997 Hz left,
1499 Hz right). Both exceed the player's 32 KiB input buffer. They contain no
third-party recordings. The checked-in files make the tests independent of
FFmpeg, external downloads, an audio device, and QEMU.

Generated with FFmpeg/libmp3lame, substituting `44100` or `48000` for `RATE`:

```sh
ffmpeg -f lavfi -i 'aevalsrc=0.2*sin(2*PI*997*t)|0.15*sin(2*PI*1499*t):s=RATE:d=2.4' \
  -codec:a libmp3lame -b:a 128k -write_xing 0 -id3v2_version 0 \
  -flags:a +bitexact -fflags +bitexact tone-RATE-stereo.mp3
```

The host regression extracts the production MP3 producer, resampler, pending
buffer, and fade functions and compiles them with the production minimp3 decoder.
It compares every PCM sample against uninterrupted input while varying read
boundaries, short reads, EOF, truncation, and trailing metadata. A single MPEG
frame verifies that the final pending block is emitted exactly once.

The harness also executes the production worker directly to check bounded stop
and resume, input errors, and audio write errors. Recognized trailing ID3v1 and
APEv2 tags are compared against the original audio without tags, so a decoder
that drops the final frame in both modes cannot accidentally pass. This is a
deterministic host test of worker behavior; SMP scheduling and QEMU audio timing
are covered separately by runtime checks.
