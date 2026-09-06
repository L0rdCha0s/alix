#!/usr/bin/env python3
"""Capture real atk_mp3 playback in an isolated eight-core QEMU guest.

This is an opt-in runtime diagnostic, requiring QEMU, ffmpeg and a populated
data.img. It uses run-via-agent.sh, copies writable firmware/data and snapshots
the kernel/player binaries. No installed guest application is used for playback.
"""

import argparse
import functools
import hashlib
import http.server
import json
import math
import os
from pathlib import Path
import pty
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import wave

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
import quake_gui_liveness_test as gui  # noqa: E402


def clone_file(source, destination):
    """Use an APFS clone when available, with an ordinary copy elsewhere."""
    if sys.platform == "darwin":
        result = subprocess.run(["cp", "-c", str(source), str(destination)],
                                capture_output=True)
        if result.returncode == 0:
            return
    shutil.copy2(source, destination)


def type_text(qmp, value, interval=0.04):
    special = {"/": "slash", ".": "dot", "-": "minus", "_": "shift-minus",
               " ": "spc", "\n": "ret"}
    keys = [special.get(char, char) for char in value]
    if interval == 0.04:
        gui.hmp_send_keys(qmp, keys)
        return
    for key in keys:
        response = qmp.human(f"sendkey {key} 20")
        if response.strip():
            raise RuntimeError(f"QMP sendkey failed: {response.strip()}")
        time.sleep(interval)


def mouse_at(qmp, x, y):
    for _ in range(14):
        gui.hmp_mouse(qmp, "mouse_move -100 -100")
    while x or y:
        dx, dy = min(100, x), min(100, y)
        gui.hmp_mouse(qmp, f"mouse_move {dx} {dy}")
        x -= dx
        y -= dy


def capture_screenshot(qmp, path):
    ppm = path.with_suffix(".ppm")
    qmp.screendump(ppm)
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
                    "-i", str(ppm), "-frames:v", "1", str(path)], check=True)


def analyse_wave(path):
    """Summarize duration and interior silence without a numerical dependency."""
    import array
    with wave.open(str(path), "rb") as wav:
        rate, channels, width, frames = (wav.getframerate(), wav.getnchannels(),
                                        wav.getsampwidth(), wav.getnframes())
        if width != 2:
            raise RuntimeError(f"expected 16-bit capture, got {width * 8} bits")
        pcm = array.array("h", wav.readframes(frames))
    if sys.byteorder != "little":
        pcm.byteswap()
    block_frames = max(1, rate // 1000)
    peaks = [max((abs(v) for v in pcm[i:i + block_frames * channels]), default=0)
             for i in range(0, len(pcm), block_frames * channels)]
    active = [i for i, peak in enumerate(peaks) if peak > 100]
    result = {"rate": rate, "channels": channels, "frames": frames,
              "capture_seconds": frames / rate, "active_seconds": 0.0,
              "interior_silence_ms": 0, "longest_silence_ms": 0}
    if active:
        first, last = active[0], active[-1]
        result["active_seconds"] = (last - first + 1) * block_frames / rate
        result["first_audio_seconds"] = first * block_frames / rate
        run = longest = total = 0
        for peak in peaks[first:last + 1]:
            if peak <= 100:
                run += 1
                total += 1
                longest = max(longest, run)
            else:
                run = 0
        result["interior_silence_ms"] = total * block_frames * 1000 / rate
        result["longest_silence_ms"] = longest * block_frames * 1000 / rate
        channel = pcm[first * block_frames * channels:(last + 1) * block_frames * channels:channels]
        result["tone_cycles"] = sum(channel[i - 1] < 0 <= channel[i]
                                    for i in range(1, len(channel)))
        coefficient = 2 * math.cos(2 * math.pi * 997 / rate)
        # A continuous sine obeys this recurrence. Abrupt edits/drops introduce
        # residual spikes; keep the raw maximum for comparison, not a generic
        # pass/fail threshold for arbitrary music.
        result["max_tone_residual"] = max((abs(channel[i] - coefficient * channel[i - 1]
                                               + channel[i - 2])
                                           for i in range(2, len(channel))), default=0)
    return result


def exercise_controls(runner, qmp, out):
    """Check worker lifetime transitions through the rendered player controls."""
    results = {}

    def capture_phase(name, expect_audio):
        path = out / f"controls-{name}.wav"
        qmp.human(f"wavcapture {path} snd0 48000 16 2")
        time.sleep(1.3)
        gui.ensure_guest_healthy(runner, gui.read_log())
        qmp.human("stopcapture 0")
        capture_screenshot(qmp, out / f"controls-{name}.png")
        results[name] = analyse_wave(path)
        has_audio = results[name]["active_seconds"] > 0.5
        if has_audio != expect_audio:
            raise RuntimeError(f"{name}: expected audio={expect_audio}, got {results[name]}")

    def click(x, y):
        mouse_at(qmp, x, y)
        gui.click_left(qmp)

    click(485, 665)
    time.sleep(0.3)
    capture_phase("restarted", True)
    click(485, 665)
    time.sleep(0.9)  # Let already-queued PCM and backend buffers drain.
    capture_phase("paused", False)
    click(485, 665)
    time.sleep(0.3)
    capture_phase("resumed", True)
    click(850, 702)
    time.sleep(0.3)
    capture_phase("seek", True)
    close_offset = len(gui.read_log())
    click(1062, 512)
    gui.wait_until(runner, "MP3 clean close", lambda t: "[atk_mp3] main exit" in t[close_offset:], 10)
    time.sleep(0.9)
    capture_phase("closed", False)
    mouse_at(qmp, 500, 950)
    gui.click_left(qmp)
    for name in ("queued_bytes", "empty_events", "reprime_events", "stream_errors",
                 "rejected_writers", "writer_pid", "running"):
        # Terminal output redraws can take longer than a HID report interval
        # under TCG. Pace these long commands so presses/releases are consumed.
        type_text(qmp, f"cat /proc/sys/audio/{name}\n", interval=0.12)
        time.sleep(1.0)
        capture_screenshot(qmp, out / f"audio-status-{name}.png")
    capture_screenshot(qmp, out / "audio-status.png")
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", default="playback")
    parser.add_argument("--backend", choices=("coreaudio", "wav", "none"), default="coreaudio")
    parser.add_argument("--use-timer", choices=("on", "off"), default="off")
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--snapshot", type=Path, help="reuse a prepared kernel/player snapshot")
    parser.add_argument("--ready-wait", type=float, default=0,
                        help="pause after the first player screenshot for inspection")
    parser.add_argument("--input-x", type=int, default=500)
    parser.add_argument("--input-y", type=int, default=632)
    parser.add_argument("--expect-clean", action="store_true",
                        help="fail on codec overruns, interior gaps or short playback")
    parser.add_argument("--exercise-controls", action="store_true",
                        help="also verify restart, pause, resume, seek and close with separate captures")
    args = parser.parse_args()
    if not args.no_build:
        subprocess.run(["make"], cwd=ROOT, check=True)
    out = ROOT / "build" / "test-out" / ("audio-" + args.label)
    out.mkdir(parents=True, exist_ok=True)
    gui.LOG_PATH = out / "serial.log"
    gui.LOG_PATH.write_text("")
    gui.harness.LOG_PATH = gui.LOG_PATH
    master, slave = pty.openpty()
    runner = qmp = server = None
    with tempfile.TemporaryDirectory(prefix="alix-audio-") as temporary:
        temp = Path(temporary)
        snap = args.snapshot.resolve() if args.snapshot else temp / "snapshot"
        if not args.snapshot:
            (snap / "EFI" / "BOOT").mkdir(parents=True)
            (snap / "http").mkdir()
            shutil.copy2(ROOT / "build" / "alix.elf", snap / "alix.elf")
            shutil.copy2(ROOT / "build" / "EFI" / "BOOT" / "BOOTX64.EFI",
                         snap / "EFI" / "BOOT" / "BOOTX64.EFI")
            shutil.copy2(ROOT / "build" / "user" / "atk_mp3.elf", snap / "http" / "atk_mp3.elf")
        boot = temp / "boot"
        (boot / "EFI" / "BOOT").mkdir(parents=True)
        shutil.copy2(snap / "alix.elf", boot / "alix.elf")
        shutil.copy2(snap / "EFI" / "BOOT" / "BOOTX64.EFI", boot / "EFI" / "BOOT" / "BOOTX64.EFI")
        clone_file(ROOT / "data.img", temp / "data.img")
        shutil.copy2(ROOT / "vendor" / "OVMF_VARS-1024x768.fd", temp / "vars.fd")
        subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
                        "-i", f"sine=frequency=997:sample_rate=44100:duration={args.seconds}",
                        "-ac", "2", "-c:a", "libmp3lame", "-b:a", "128k", str(snap / "http" / "tone.mp3")],
                       check=True)
        wrapper = temp / "qemu-audio-wrapper"
        real_qemu = shutil.which("qemu-system-x86_64")
        if not real_qemu:
            raise RuntimeError("qemu-system-x86_64 is unavailable")
        wrapper.write_text("#!/usr/bin/env python3\nimport os, sys\n"
                           "args = sys.argv[1:]\n"
                           f"args = [a.replace('file=fat:rw:build,', 'file=fat:rw:{boot},') for a in args]\n"
                           f"os.execv({real_qemu!r}, [{real_qemu!r}] + args)\n")
        wrapper.chmod(0o755)
        trace = out / "qemu-trace.log"
        events = temp / "trace-events"
        events.write_text("hda_audio_running\nhda_audio_format\nhda_audio_adjust\n"
                          "hda_audio_overrun\naudio_timer_delayed\n")
        capture = out / "capture.wav"
        qmp_path = temp / "qmp.sock"
        env = os.environ.copy()
        # Command-variable overrides preserve isolation despite := in Makefile.
        env["MAKEFLAGS"] = (f"QEMU={wrapper} OVMF_VARS={temp / 'vars.fd'} "
                            f"SMP_CORES=8 QEMU_ACCEL=tcg HDA_MODEL=hda-output,use-timer={args.use_timer}")
        env.update({"NETDUMP": "", "QEMU_DEBUG_FLAGS": f"-trace events={events},file={trace}",
                    "QEMU_GDB_FLAGS": f"-display none -qmp unix:{qmp_path},server,nowait -pidfile {temp / 'qemu.pid'}",
                    "QEMU_DATA_IMG": str(temp / "data.img"), "QEMU_SERIAL_LOG": str(gui.LOG_PATH),
                    "QEMU_TIMEOUT_SECONDS": "240", "AUDIO_DEV": args.backend})
        if args.backend == "wav":
            env["AUDIO_DEV"] = f"wav,path={capture},out.frequency=48000"
        metadata = {"backend": args.backend, "use_timer": args.use_timer, "cores": 8,
                    "expected_seconds": args.seconds,
                    "kernel_sha256": hashlib.sha256((snap / "alix.elf").read_bytes()).hexdigest(),
                    "player_sha256": hashlib.sha256((snap / "http" / "atk_mp3.elf").read_bytes()).hexdigest(),
                    "qemu_version": subprocess.check_output([real_qemu, "--version"], text=True).splitlines()[0]}
        try:
            handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(snap / "http"))
            server = socketserver.TCPServer(("127.0.0.1", 0), handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            port = server.server_address[1]
            print(f"Starting isolated playback: {out}", flush=True)
            runner = subprocess.Popen([str(ROOT / "run-via-agent.sh")], cwd=ROOT, env=env,
                                      stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                      start_new_session=True)
            os.close(slave)
            slave = -1
            gui.wait_until(runner, "login prompt", lambda t: "login:" in t, 60)
            gui.harness.send_serial(master, "root\r")
            gui.wait_until(runner, "password prompt", lambda t: "password:" in t, 10)
            gui.harness.send_serial(master, "root\r")
            gui.wait_until(runner, "shell prompt", lambda t: "root@alix$" in t, 15)
            offset = len(gui.read_log())
            gui.harness.send_serial(master, "mkdir /tmp\r")
            gui.wait_until(runner, "temporary directory", lambda t: "root@alix$" in t[offset:], 15)
            for filename in ("atk_mp3.elf", "tone.mp3"):
                offset = len(gui.read_log())
                gui.harness.send_serial(master, f"wget http://10.0.2.2:{port}/{filename} /tmp/{filename}\r")
                expected = f"Saved {(snap / 'http' / filename).stat().st_size} bytes to /tmp/{filename}"
                gui.wait_until(runner, f"fresh {filename} download", lambda t: expected in t[offset:], 60)
            offset = len(gui.read_log())
            gui.harness.send_serial(master, "start_video\r")
            gui.wait_until(runner, "video loop", lambda t: "video_run_loop start" in t[offset:], 20)
            qmp = gui.QmpClient(qmp_path)
            gui.move_mouse_to_terminal(qmp)
            gui.click_left(qmp)
            gui.wait_until(runner, "desktop terminal", lambda t: "start name=atk_shell" in t[offset:], 15)
            time.sleep(1)
            type_text(qmp, "/tmp/atk_mp3.elf\n")
            gui.wait_until(runner, "MP3 first present", lambda t: "[atk_mp3] first present" in t[offset:], 35)
            time.sleep(1)
            capture_screenshot(qmp, out / "player-ready.png")
            print(f"Player ready screenshot: {out / 'player-ready.png'}", flush=True)
            if args.ready_wait:
                time.sleep(args.ready_wait)
            if args.backend != "wav":
                response = qmp.human(f"wavcapture {capture} snd0 48000 16 2")
                if response.strip():
                    print(f"Capture: {response.strip()}", flush=True)
            mouse_at(qmp, args.input_x, args.input_y)
            gui.click_left(qmp)
            type_text(qmp, "/tmp/tone.mp3\n")
            time.sleep(1)
            capture_screenshot(qmp, out / "player-playing.png")
            print("Playback started; recording controlled tone", flush=True)
            deadline = time.monotonic() + args.seconds + 8
            while time.monotonic() < deadline:
                gui.ensure_guest_healthy(runner, gui.read_log())
                time.sleep(0.1)
            capture_screenshot(qmp, out / "player-finished.png")
            if args.backend != "wav":
                qmp.human("stopcapture 0")
            if args.exercise_controls:
                if args.backend == "wav":
                    raise RuntimeError("control captures require --backend coreaudio or none")
                metadata["controls"] = exercise_controls(runner, qmp, out)
            qmp.quit()
            runner.wait(timeout=10)
            qmp.close()
            qmp = None
            metadata.update(analyse_wave(capture))
            trace_text = trace.read_text(errors="replace")
            metadata["codec_overruns"] = trace_text.count("hda_audio_overrun")
            metadata["timer_adjustments"] = trace_text.count("hda_audio_adjust")
            metadata["audio_timer_delayed"] = trace_text.count("audio_timer_delayed")
            metadata["serial_ring_empty_logs"] = gui.read_log().count("[hda] ring empty")
            (out / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")
            print(json.dumps(metadata, indent=2), flush=True)
            if not metadata["active_seconds"]:
                raise RuntimeError("capture has no audible PCM; inspect player screenshots")
            if args.expect_clean and (metadata["codec_overruns"] or metadata["longest_silence_ms"] > 5
                                      or abs(metadata["active_seconds"] - args.seconds) > 0.15
                                      or abs(metadata["tone_cycles"] - 997 * args.seconds) > 100
                                      or metadata["max_tone_residual"] > 50):
                raise RuntimeError("playback failed continuity/duration checks; inspect result.json")
        finally:
            if qmp:
                try:
                    qmp.quit()
                except Exception:
                    pass
                qmp.close()
            if runner:
                gui.stop_subprocess(runner)
            if server:
                server.shutdown()
                server.server_close()
            os.close(master)
            if slave >= 0:
                os.close(slave)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, gui.harness.StressFailure) as error:
        print(f"audio playback diagnostic failed: {error}", file=sys.stderr)
        raise SystemExit(1)
