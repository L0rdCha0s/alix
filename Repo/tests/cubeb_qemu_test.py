#!/usr/bin/env python3
"""Exercise upstream cubeb/Speex on real Alix HDA and inspect captured mixing."""
import argparse
import array
import hashlib
import json
import math
from pathlib import Path
import sys
import wave

from cpp_runtime_qemu_test import ROOT, run_native_elf


def analyse_mix(path):
    with wave.open(str(path), "rb") as recording:
        rate = recording.getframerate()
        channels = recording.getnchannels()
        if (rate, channels, recording.getsampwidth()) != (48000, 2, 2):
            raise RuntimeError("capture is not the actual 48 kHz stereo S16 output")
        pcm = array.array("h", recording.readframes(recording.getnframes()))
    if sys.byteorder != "little":
        pcm.byteswap()
    samples = pcm[::channels]
    length = rate // 20
    best = None
    # Both independent tones must occur in the same 50 ms window. Verify their
    # expected volume ratio and energy against unrelated frequency controls;
    # sequential playback, one stream alone, or broad noise cannot pass.
    for start in range(0, len(samples) - length, length // 5):
        segment = samples[start:start + length]
        amplitudes = {}
        for frequency in (503, 997, 137, 1601, 3119):
            angle = 2 * math.pi * frequency / rate
            real = sum(value * math.cos(angle * index) for index, value in enumerate(segment))
            imaginary = sum(value * math.sin(angle * index) for index, value in enumerate(segment))
            amplitudes[frequency] = 2 * math.hypot(real, imaginary) / length
        native, resampled = amplitudes[503], amplitudes[997]
        noise = max(amplitudes[frequency] for frequency in (137, 1601, 3119))
        energy = sum(value * value for value in segment) / length
        explained = (native * native + resampled * resampled) / (2 * energy) if energy else 0
        if (min(native, resampled) > 100 and 1.3 < resampled / native < 1.7 and
                0.9 < explained < 1.1 and noise < min(native, resampled) * 0.1):
            candidate = {"start_seconds": start / rate, "window_seconds": length / rate,
                         "tone_amplitudes_s16": amplitudes, "explained_energy_fraction": explained,
                         "minimum_amplitude": min(native, resampled)}
            if best is None or candidate["minimum_amplitude"] > best["minimum_amplitude"]:
                best = candidate
    if best is None:
        raise RuntimeError("no captured window contains both expected mixed tones")
    return {"rate": rate, "channels": channels, "frames": len(samples),
            "simultaneous_tones": best,
            "scope": "Concurrent tone mixing and conversion; not full audio quality or cubeb conformance."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiler-provider", action="store_true")
    args = parser.parse_args()
    name = "cubeb_alix_profiler_test.elf" if args.profiler_provider else "cubeb_alix_test.elf"
    stem = "cubeb-native-profiler" if args.profiler_provider else "cubeb-native"
    log = ROOT / "build/test-out" / (stem + "-qemu.log")
    capture = log.with_suffix(".wav")
    markers = ["CUBEB_ALIX_TEST: MIX PASS resample44100=11025 stereo48000=12000"]
    if args.profiler_provider:
        markers += ["CUBEB_ALIX_TEST: PROFILER PASS linked=1 thread_lifetimes=3"]
    markers += ["CUBEB_ALIX_TEST: PASS contexts=2 streams=3 resample=1 restart=1 pause=1 self_destroy=1"]
    binary = ROOT / "build/user" / name
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    build = json.loads((ROOT / "build/ports/zen" / (binary.stem + "-build.json")).read_text())
    if build["elf_sha256"] != digest or build["linked_profiler"] != args.profiler_provider:
        raise RuntimeError("cubeb executable does not match its build receipt")
    run_native_elf(name, markers, log, "actual upstream cubeb and Speex", timeout_seconds=55,
                   expected_wait_status=0, fail_on_missing_markers_at_exit=True,
                   audio_capture_path=capture)
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise RuntimeError("cubeb acceptance ELF changed during the run")
    result = analyse_mix(capture)
    result.update({"elf": str(binary), "elf_sha256": digest, "log": str(log),
                   "capture": str(capture), "linked_profiler": args.profiler_provider,
                   "build": build,
                   "boot_images": json.loads(log.with_suffix(".boot-image.json").read_text())})
    log.with_suffix(".acceptance.json").write_text(json.dumps(result, indent=2) + "\n")
    print("Hardware capture contains simultaneous 503 Hz and 997 Hz streams: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
