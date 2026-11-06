# Zen HTML5 media investigation, 6 November 2026

The original Alix package reports no supported WebM video codecs in content
processes. Enabling the existing local decoders exposes two further runtime
crashes: an uninitialized HAL wake-lock table and a missing boot-clock API.
The source fixes passed the full native Gecko build/link and actual direct,
Media Source and YouTube playback in eight-core QEMU guests. The validated
package is now the default `build/ports/zen/zen-browser.zip`.

Evidence is retained under `build/perf/zen-media-20261106/`. Every guest uses a
private data-image clone. The original data image is never booted in place.

The combined candidate has libxul build ID
`0312e95f232ab649c486b16a9a43556aff9edb95`. Its complete Gecko build took
25 minutes 10 seconds. Packaging passed the existing load/TLS checks for
26 native ELF images and staged 50 payload files, including the platform
preference. Frozen symbols and the complete build log are retained alongside it.

## Decoder selection

The original libxul build ID is
`ad123f1f76881432b5813691a165a827ddc1640c`.
`capabilities-before/result.json` records the actual content-process results:
VP8/Vorbis, VP9/Opus, VP9, AV1 and WebM Opus all have empty `canPlayType`
responses and false Media Source support. Both remote decoder process defaults
are disabled for Alix, while `media.allow-audio-non-utility` also defaults false.
`PDMFactory` gates local video modules on this preference as well as audio.

The private control run `capabilities-local-control` changes only that preference
and obtains positive WebM codec and Media Source responses. The native package
now installs `defaults/pref/alix.js` with
`media.allow-audio-non-utility=true`, permitting the bundled software decoders
in the existing content processes. The archive manifest includes this file.
No codec responses are fabricated. H.264/AAC remain unsupported by this build.

## Wake-lock initialization

Actual VP9/Opus playback with the decoder preference enabled reaches 320 by 180
metadata, then crashes the parent process with SIGSEGV. The original fault is
`libxul+0x15ca907`, with RSI zero, page-fault address 8, trap 14. Symbolization
places the call in `mozilla::hal_impl::ModifyWakeLockWithChildID` through
`PLDHashTable::MakeEntryHandle`.

`sLockTable` is initialized by `hal::WakeLockInit`, called from `hal::Init`.
The Alix app shell omitted the HAL lifecycle present in other widget backends.
Its initialization now calls `hal::Init` after the base app shell succeeds;
destruction calls `hal::Shutdown` only after successful initialization.
The canonical source is retained in patch 0015 with updated hash guards.

The `old-fault-context-confirm-retry` evaluation reproduces the original fault
using the corrected fault collector. The collector reads the actual userspace
signal frame, checks its magic and resolves the original PC against the live
module build ID and instruction bytes. The kernel delivery scratch image is
not the original fault context and is not used for this attribution.

## Boot clock and audio sessions

The HAL-only rebuilt libxul has build ID
`e3170545969398b05b6a3bfda3025c591ed34c1d`. Its `direct-fixed` run passes the
wake-lock operation, then hits `MOZ_RELEASE_ASSERT(isSome())` at
`libxul+0x386f83a`, in `AudioSessionManager::NotifyAudibilityChanged`.
`ProcessUptimeMs` returns `Nothing`: Gecko's Unix `NowIncludingSuspendMs`
does not have a clock implementation without `CLOCK_BOOTTIME`.

The shared Alix time API now defines and implements `CLOCK_BOOTTIME` for
`clock_gettime` and `clock_getres`. Alix currently has no system-suspend path,
so this clock uses the existing monotonic clock domain. Future suspend support
must account for suspended time here. Invalid clock IDs still fail normally.
The original object unconditionally returned `Nothing`; the rebuilt object now
calls `clock_gettime(7, ...)` and propagates a real successful timestamp.

The existing perf app has an opt-in `syscall/boot_clock` evaluation. It verifies
a monotonic bracket, positive resolution, advancement across a 20 ms sleep and
nondecreasing reads. `boot-clock-native.log` records PASS in an eight-core guest.
The existing host time and CPU-clock checks also pass. This is clock behavior
evidence, not completed browser playback acceptance or a speed comparison.

## Playback diagnostics

The existing browser evaluator can now collect MIME/Media Source capabilities,
prepare a generated VP9/Opus fixture as a direct resource or chunked Media
Source, and start playback through trusted native input. It records frame
callbacks, presentation timestamps, dropped-frame counters, media state and
errors. Two native framebuffer captures check that the video image changes.
The optional WAV backend records the emulated guest audio output.

`--media-live` exercises visible YouTube controls using native input. The
successful live run focuses the visible Play control and presses native Enter;
the page records a trusted click. Earlier pointer attempts did not activate
playback while YouTube hydrated its layout. Those failures remain recorded as
input failures, rather than decoder failures.
`--fault-profile` captures fatal signals before process teardown, including
original userspace register context, module identity and crash reason. Debugger
and media diagnostics are explicitly marked as perturbing performance timing.

The generated four-second fixture uses 320 by 180 VP9 at 15 fps and a 997 Hz
Opus tone. Codec advertisement alone is not playback acceptance. Direct video,
Media Source, captured audio, native moving pixels and live YouTube playback
have separate recorded evidence.

## Native outcome and delivery

| Run | Playback observation | Native changed video pixels | Captured non-silent audio |
| --- | --- | ---: | ---: |
| `direct-clock` | 320 by 180, 20 frames, 1 dropped | 25,036 | 20.46 s, approximately 997 Hz tone |
| `mse-clock` | 320 by 180, 14 frames, 0 dropped, 3 appends | 22,613 | 22.99 s tone |
| `youtube-focused` | Me at the zoo, 320 by 240, current time 4.132 s, 284 frames, 32 dropped | 1,126 | 18.87 s |

All three runs verify 93 installed file hashes and report unmuted playback,
zero media errors, zero fatal page
faults, zero kernel-heap allocation failures, exit status zero and a guest-origin
OS shutdown. Their source-image identity, size and modification time remain
unchanged. The live resource uses a `blob:` Media Source URL. Its trusted native
Enter activation is recorded by the page's actual Play-button click listener.
The two YouTube video-region captures differ around the face, including all
1,126 changed pixels when the bottom 96 pixels are excluded. This separately
rules out the progress controls as the source of the native image change.
`youtube-focused/youtube-native.png` retains the real framebuffer screenshot.

These are functional playback checks, not proof of smooth playback. The direct
tone capture has 3.45 s of interior silence across its 23.91 s active span,
with a longest gap of 149 ms; the Media Source capture has 158 ms total and a
58 ms maximum gap. The captures include debugger/lifecycle operations, so these
figures are not attributed to a specific component. YouTube's 32 dropped frames
and sparse frame callbacks also remain performance follow-up evidence. Silence
in the natural YouTube soundtrack is not classified as an underrun. Physical
display/speaker playback and H.264/AAC support are not established here.

The published archive SHA-256 is
`06c82d746f491e70ae0699103077648ac8919eeef57955be50e0b72a4f54ddcb`.
Every payload hash and all staged bytes were checked before promotion. The
previous R8-fixed package and staging directory are retained as
`build/ports/zen/zen-browser.before-html5-media-20261106.zip` and the matching
directory without `.zip`. The R8 rendering fix remains present in the new build.

`make`, patch hash verification, existing time/CPU-clock checks and Node/Python
syntax checks pass. All eight kernel stack-debug flags remain zero. The running
browser on the original user image is not replaced by these private boots;
run `./serve-dl.sh` on the Mac, close Zen, then run the existing `dl-zen.sh`
updater in Alix to install the new default bundle. The host server is not
currently running. Profiles are outside the application bundle.
