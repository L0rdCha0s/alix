#!/usr/bin/env python3
"""Exercise Quake through the real desktop compositor and prove it stays live."""

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import os
import pty
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "build" / "test-out"
LOG_PATH = OUT_DIR / "quake-gui-liveness.log"
QUAKE_ELF = ROOT / "build" / "user" / "quake.elf"
SCREENSHOTS = [
    OUT_DIR / "quake-gui-liveness-1.ppm",
    OUT_DIR / "quake-gui-liveness-2.ppm",
    OUT_DIR / "quake-gui-liveness-3.ppm",
    OUT_DIR / "quake-gui-liveness-post-input.ppm",
]

sys.path.insert(0, str(ROOT / "tests"))
import process_lock_stress_test as harness  # noqa: E402


HEARTBEAT_RE = re.compile(
    r"\[quake\]\[liveness\]\s+"
    r"ms=(?P<ms>\d+)\s+"
    r"frames=(?P<frames>\d+)\s+"
    r"presents_ok=(?P<presents_ok>\d+)\s+"
    r"presents_fail=(?P<presents_fail>\d+)\s+"
    r"input=(?P<input>\d+)\s+"
    r"key=(?P<key>\d+)\s+"
    r"mouse=(?P<mouse>\d+)\s+"
    r"src_hash=(?P<src_hash>[0-9A-Fa-f]{8})"
)
FAILURE_RE = re.compile(
    harness.FAILURE_RE.pattern + r"|=== CPU EXCEPTION ===",
    re.IGNORECASE,
)

# The 960x600 Quake client is clamped to the bottom-right of the 1280x1024
# desktop. This crop is wholly inside its client area (x=312..1271,
# y=416..1015) and stays away from the injected mouse position.
QUAKE_ROI = (800, 500, 400, 400)


@dataclass(frozen=True)
class Heartbeat:
    ms: int
    frames: int
    presents_ok: int
    presents_fail: int
    input_events: int
    key_events: int
    mouse_events: int
    source_hash: str


class QmpClient:
    """Small synchronous QMP client which tolerates asynchronous QMP events."""

    def __init__(self, socket_path: Path, timeout: float = 5.0) -> None:
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(1.0)
        deadline = time.monotonic() + timeout
        while True:
            try:
                self._socket.connect(str(socket_path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    self._socket.close()
                    raise harness.StressFailure("QMP socket did not become ready")
                time.sleep(0.05)

        self._stream = self._socket.makefile("rwb", buffering=0)
        if not self._read_message(deadline):
            self.close()
            raise harness.StressFailure("QMP closed before its greeting")
        self._next_id = 1
        self.execute("qmp_capabilities")

    def _read_message(self, deadline: float):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise harness.StressFailure("timed out waiting for QMP response")
        self._socket.settimeout(remaining)
        try:
            line = self._stream.readline()
        except socket.timeout as error:
            raise harness.StressFailure("timed out waiting for QMP response") from error
        if not line:
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError as error:
            raise harness.StressFailure(f"invalid QMP response: {line!r}") from error

    def execute(self, command: str, arguments=None, timeout: float = 5.0):
        request_id = self._next_id
        self._next_id += 1
        request = {"execute": command, "id": request_id}
        if arguments is not None:
            request["arguments"] = arguments
        try:
            self._stream.write(json.dumps(request).encode("ascii") + b"\r\n")
        except (BrokenPipeError, OSError) as error:
            raise harness.StressFailure(f"QMP closed while sending {command}") from error

        deadline = time.monotonic() + timeout
        while True:
            response = self._read_message(deadline)
            if response is None:
                raise harness.StressFailure(f"QMP closed while executing {command}")
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise harness.StressFailure(
                    f"QMP command {command} failed: {response['error']}"
                )
            if "return" in response:
                return response["return"]

    def human(self, command: str) -> str:
        result = self.execute(
            "human-monitor-command", {"command-line": command}
        )
        return result if isinstance(result, str) else ""

    def screendump(self, path: Path) -> None:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        result = self.human(f"screendump {path}")
        if result.strip():
            raise harness.StressFailure(
                f"QMP screendump reported an error for {path.name}: {result.strip()}"
            )
        if not path.is_file() or path.stat().st_size == 0:
            raise harness.StressFailure(f"QMP did not create {path.name}")

    def quit(self) -> None:
        # QEMU normally returns success before closing, but accepting EOF here
        # keeps cleanup reliable across QEMU versions.
        try:
            self.execute("quit", timeout=3.0)
        except harness.StressFailure as error:
            if "QMP closed" not in str(error):
                raise

    def close(self) -> None:
        try:
            self._stream.close()
        except (AttributeError, OSError):
            pass
        try:
            self._socket.close()
        except OSError:
            pass


def read_log() -> str:
    try:
        return LOG_PATH.read_bytes().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def start_http_server() -> tuple[subprocess.Popen[bytes], int]:
    """Serve the current build to QEMU's 10.0.2.2 slirp host address."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = int(probe.getsockname()[1])
    probe.close()

    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "http.server",
            str(port),
            "--bind",
            "127.0.0.1",
        ],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise harness.StressFailure("local Quake HTTP server exited during startup")
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.settimeout(0.2)
        try:
            connection.connect(("127.0.0.1", port))
            return server, port
        except (ConnectionRefusedError, socket.timeout):
            time.sleep(0.05)
        finally:
            connection.close()
    server.terminate()
    server.wait(timeout=2.0)
    raise harness.StressFailure("local Quake HTTP server did not become ready")


def stop_subprocess(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2.0)


def ensure_guest_healthy(runner: subprocess.Popen[bytes], text: str) -> None:
    if runner.poll() is not None:
        raise harness.StressFailure("QEMU exited unexpectedly")
    failure = FAILURE_RE.search(text)
    if failure:
        raise harness.StressFailure(
            f"kernel failure marker found: {failure.group(0)!r}"
        )


def wait_until(runner: subprocess.Popen[bytes], label: str, predicate, timeout: float):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = read_log()
        ensure_guest_healthy(runner, text)
        value = predicate(text)
        if value is not None and value is not False:
            return value
        time.sleep(0.05)
    raise harness.StressFailure(f"timed out waiting for {label}")


def parse_heartbeats(text: str, offset: int) -> list[Heartbeat]:
    records = []
    for match in HEARTBEAT_RE.finditer(text[offset:]):
        records.append(
            Heartbeat(
                ms=int(match.group("ms")),
                frames=int(match.group("frames")),
                presents_ok=int(match.group("presents_ok")),
                presents_fail=int(match.group("presents_fail")),
                input_events=int(match.group("input")),
                key_events=int(match.group("key")),
                mouse_events=int(match.group("mouse")),
                source_hash=match.group("src_hash").upper(),
            )
        )
    return records


def validate_heartbeats(records: list[Heartbeat]) -> None:
    for record in records:
        if record.presents_fail != 0:
            raise harness.StressFailure(
                f"Quake reported {record.presents_fail} failed presents"
            )
        if record.presents_ok != record.frames:
            raise harness.StressFailure(
                "Quake frame/present counters diverged: "
                f"frames={record.frames} presents_ok={record.presents_ok}"
            )
    for previous, current in zip(records, records[1:]):
        if current.frames <= previous.frames:
            raise harness.StressFailure(
                f"Quake frames stopped advancing at {current.frames}"
            )
        if current.presents_ok <= previous.presents_ok:
            raise harness.StressFailure(
                f"Quake presents stopped advancing at {current.presents_ok}"
            )


def wait_for_heartbeats(
    runner: subprocess.Popen[bytes],
    offset: int,
    label: str,
    predicate,
    timeout: float,
) -> list[Heartbeat]:
    def ready(text: str):
        records = parse_heartbeats(text, offset)
        validate_heartbeats(records)
        return records if predicate(records) else None

    return wait_until(runner, label, ready, timeout)


def hmp_send_keys(qmp: QmpClient, keys: list[str]) -> None:
    for key in keys:
        result = qmp.human(f"sendkey {key} 20")
        if result.strip():
            raise harness.StressFailure(
                f"QMP sendkey {key!r} failed: {result.strip()}"
            )
        # Keep the USB HID report below its simultaneous-key limit and give the
        # guest keyboard poller a chance to consume each press/release pair.
        time.sleep(0.04)


def hmp_mouse(qmp: QmpClient, command: str) -> None:
    result = qmp.human(command)
    if result.strip():
        raise harness.StressFailure(
            f"QMP mouse command {command!r} failed: {result.strip()}"
        )
    time.sleep(0.03)


def move_mouse_to_terminal(qmp: QmpClient) -> None:
    # Establish a known origin, then move to the centre of the desktop's fixed
    # Terminal tile (x=340..427, y=80..167).
    for _ in range(14):
        hmp_mouse(qmp, "mouse_move -100 -100")
    for dx, dy in ((100, 100), (100, 24), (100, 0), (84, 0)):
        hmp_mouse(qmp, f"mouse_move {dx} {dy}")


def click_left(qmp: QmpClient) -> None:
    hmp_mouse(qmp, "mouse_button 1")
    hmp_mouse(qmp, "mouse_button 0")


def move_mouse_into_quake(qmp: QmpClient) -> None:
    # Clamp at bottom-right and return to roughly (580, 720), which is inside
    # Quake but outside QUAKE_ROI. Small deltas avoid USB report clipping.
    for _ in range(14):
        hmp_mouse(qmp, "mouse_move 100 100")
    for _ in range(7):
        hmp_mouse(qmp, "mouse_move -100 0")
    for _ in range(3):
        hmp_mouse(qmp, "mouse_move 0 -100")


def ppm_pixels(path: Path):
    data = path.read_bytes()
    position = 0
    tokens = []
    while len(tokens) < 4:
        while position < len(data) and data[position] in b" \t\r\n":
            position += 1
        if position < len(data) and data[position] == ord("#"):
            while position < len(data) and data[position] not in b"\r\n":
                position += 1
            continue
        start = position
        while position < len(data) and data[position] not in b" \t\r\n":
            position += 1
        if start == position:
            raise harness.StressFailure(f"invalid PPM header in {path.name}")
        tokens.append(data[start:position])

    if tokens[0] != b"P6":
        raise harness.StressFailure(f"unsupported screendump format in {path.name}")
    try:
        width, height, maximum = (int(token) for token in tokens[1:])
    except ValueError as error:
        raise harness.StressFailure(f"invalid PPM dimensions in {path.name}") from error
    if maximum != 255 or width <= 0 or height <= 0:
        raise harness.StressFailure(f"invalid PPM geometry in {path.name}")

    if position >= len(data) or data[position] not in b" \t\r\n":
        raise harness.StressFailure(f"missing PPM pixel separator in {path.name}")
    if data[position:position + 2] == b"\r\n":
        position += 2
    else:
        position += 1
    expected = width * height * 3
    pixels = data[position:position + expected]
    if len(pixels) != expected:
        raise harness.StressFailure(f"truncated screendump {path.name}")
    return width, height, pixels


def roi_hash(path: Path) -> str:
    width, height, pixels = ppm_pixels(path)
    x, y, roi_width, roi_height = QUAKE_ROI
    if x + roi_width > width or y + roi_height > height:
        raise harness.StressFailure(
            f"Quake ROI does not fit {path.name} ({width}x{height})"
        )
    digest = hashlib.sha256()
    for row in range(y, y + roi_height):
        start = (row * width + x) * 3
        digest.update(pixels[start:start + roi_width * 3])
    return digest.hexdigest()


def capture_after_progress(
    runner: subprocess.Popen[bytes],
    qmp: QmpClient,
    offset: int,
    prior_count: int,
    path: Path,
) -> tuple[list[Heartbeat], str]:
    records = wait_for_heartbeats(
        runner,
        offset,
        f"new heartbeat before {path.name}",
        lambda items: len(items) >= prior_count + 2,
        12.0,
    )
    time.sleep(0.2)
    qmp.screendump(path)
    return records, roi_hash(path)


def main() -> int:
    if not QUAKE_ELF.is_file() or QUAKE_ELF.stat().st_size == 0:
        print(f"Quake GUI liveness test failed: missing {QUAKE_ELF}", file=sys.stderr)
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("", encoding="utf-8")
    for path in SCREENSHOTS:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    harness.LOG_PATH = LOG_PATH

    master_fd, slave_fd = pty.openpty()
    runner = None
    qmp = None
    quit_sent = False
    http_server = None
    with tempfile.TemporaryDirectory(prefix="alix-quake-gui-") as temp_dir:
        temp = Path(temp_dir)
        qmp_path = temp / "qmp.sock"
        pid_path = temp / "qemu.pid"
        env = os.environ.copy()
        env.update(
            {
                "AUDIO_DEV": "none",
                "NETDUMP": "",
                "QEMU_DEBUG_FLAGS": "",
                "QEMU_GDB_FLAGS": (
                    f"-qmp unix:{qmp_path},server,nowait -pidfile {pid_path}"
                ),
                "QEMU_SERIAL_LOG": str(LOG_PATH),
                "QEMU_TIMEOUT_SECONDS": "180",
            }
        )

        try:
            http_server, http_port = start_http_server()
            runner = subprocess.Popen(
                [str(ROOT / "run-via-agent.sh")],
                cwd=ROOT,
                env=env,
                stdin=slave_fd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            os.close(slave_fd)
            slave_fd = -1

            wait_until(runner, "login prompt", lambda text: "login:" in text, 30.0)
            harness.send_serial(master_fd, "root\r")
            wait_until(
                runner, "password prompt", lambda text: "password:" in text, 5.0
            )
            harness.send_serial(master_fd, "root\r")
            wait_until(
                runner, "shell prompt", lambda text: "root@alix$" in text, 10.0
            )

            mkdir_start = len(read_log())
            harness.send_serial(master_fd, "mkdir /tmp\r")
            wait_until(
                runner,
                "shell prompt after creating /tmp",
                lambda text: "root@alix$" in text[mkdir_start:],
                10.0,
            )
            download_start = len(read_log())
            guest_elf = "/tmp/quake-liveness.elf"
            harness.send_serial(
                master_fd,
                (
                    f"wget http://10.0.2.2:{http_port}/build/user/quake.elf "
                    f"{guest_elf}\r"
                ),
            )
            expected_saved = (
                f"Saved {QUAKE_ELF.stat().st_size} bytes to {guest_elf}"
            )
            wait_until(
                runner,
                "fresh Quake ELF download",
                lambda text: (
                    expected_saved in text[download_start:]
                    and "root@alix$" in text[
                        text.find(expected_saved, download_start) + len(expected_saved):
                    ]
                ),
                60.0,
            )

            video_start = len(read_log())
            harness.send_serial(master_fd, "start_video\r")
            wait_until(
                runner,
                "video loop",
                lambda text: (
                    "[thread_trampoline] start name=start_video" in text[video_start:]
                    and "video_run_loop start" in text[video_start:]
                ),
                15.0,
            )

            qmp = QmpClient(qmp_path)
            terminal_start = len(read_log())
            move_mouse_to_terminal(qmp)
            click_left(qmp)
            wait_until(
                runner,
                "desktop Terminal process",
                lambda text: "[thread_trampoline] start name=atk_shell" in text[terminal_start:],
                10.0,
            )
            time.sleep(1.0)

            quake_start = len(read_log())
            command_keys = [
                "slash", "t", "m", "p", "slash", "q", "u", "a", "k", "e",
                "minus", "l", "i", "v", "e", "n", "e", "s", "s", "dot",
                "e", "l", "f",
                "spc", "minus", "l", "i", "v", "e", "n", "e", "s", "s",
                "minus", "t", "e", "s", "t", "ret",
            ]
            hmp_send_keys(qmp, command_keys)
            wait_until(
                runner,
                "Quake video initialization",
                lambda text: "[quake][video] VID_Init done" in text[quake_start:],
                35.0,
            )

            records = wait_for_heartbeats(
                runner,
                quake_start,
                "four advancing Quake heartbeats with changing source frames",
                lambda items: (
                    len(items) >= 4
                    and len({item.source_hash for item in items}) >= 2
                ),
                25.0,
            )

            time.sleep(0.2)
            qmp.screendump(SCREENSHOTS[0])
            roi_hashes = [roi_hash(SCREENSHOTS[0])]
            for screenshot in SCREENSHOTS[1:3]:
                records, digest = capture_after_progress(
                    runner, qmp, quake_start, len(records), screenshot
                )
                roi_hashes.append(digest)

            if len(set(roi_hashes)) < 2:
                raise harness.StressFailure(
                    "Quake source frames advanced but the compositor ROI stayed unchanged"
                )

            input_baseline = records[-1]
            move_mouse_into_quake(qmp)
            click_left(qmp)
            hmp_mouse(qmp, "mouse_move 12 7")
            hmp_send_keys(qmp, ["shift"])

            records = wait_for_heartbeats(
                runner,
                quake_start,
                "Quake mouse and key counters",
                lambda items: (
                    items
                    and items[-1].mouse_events > input_baseline.mouse_events
                    and items[-1].key_events > input_baseline.key_events
                ),
                12.0,
            )
            input_observed = records[-1]
            records = wait_for_heartbeats(
                runner,
                quake_start,
                "continued rendering after input",
                lambda items: (
                    len(items) >= 3
                    and items[-1].ms >= input_observed.ms + 3000
                    and items[-1].frames > input_observed.frames
                    and items[-1].presents_ok > input_observed.presents_ok
                    and any(
                        item.source_hash != input_observed.source_hash
                        for item in items[-3:]
                    )
                ),
                15.0,
            )
            time.sleep(0.2)
            qmp.screendump(SCREENSHOTS[3])
            post_input_roi = roi_hash(SCREENSHOTS[3])
            if post_input_roi == roi_hashes[-1]:
                raise harness.StressFailure(
                    "Quake compositor ROI did not change after input and later heartbeats"
                )

            final_log = read_log()
            ensure_guest_healthy(runner, final_log)
            if "video_run_loop end" in final_log[video_start:]:
                raise harness.StressFailure("video loop exited unexpectedly")

            qmp.quit()
            quit_sent = True
            qmp.close()
            qmp = None
            runner.wait(timeout=10.0)

            source_hashes = {item.source_hash for item in records}
            print(
                "Quake GUI liveness test passed: "
                f"heartbeats={len(records)} frames={records[-1].frames} "
                f"presents={records[-1].presents_ok} failures=0 "
                f"source_hashes={len(source_hashes)} roi_hashes={len(set(roi_hashes + [post_input_roi]))} "
                f"key={records[-1].key_events} mouse={records[-1].mouse_events}"
            )
            print(f"serial log: {LOG_PATH}")
            print("screenshots: " + ", ".join(str(path) for path in SCREENSHOTS))
            return 0
        except (harness.StressFailure, subprocess.TimeoutExpired, OSError) as error:
            print(f"Quake GUI liveness test failed: {error}", file=sys.stderr)
            print(f"serial log: {LOG_PATH}", file=sys.stderr)
            return 1
        finally:
            if qmp is not None:
                if not quit_sent:
                    try:
                        qmp.quit()
                    except (harness.StressFailure, OSError):
                        pass
                qmp.close()
            if slave_fd >= 0:
                os.close(slave_fd)
            os.close(master_fd)
            if pid_path.exists():
                try:
                    harness.stop_process(int(pid_path.read_text(encoding="ascii").strip()))
                except (OSError, ValueError):
                    pass
            if runner is not None and runner.poll() is None:
                try:
                    os.killpg(runner.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    runner.wait(timeout=3.0)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(runner.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if http_server is not None:
                stop_subprocess(http_server)


if __name__ == "__main__":
    raise SystemExit(main())
