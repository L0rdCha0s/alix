#!/usr/bin/env python3
"""Verify that work queued to an idle AP wakes and starts the GUI loop."""

from pathlib import Path
import json
import os
import pty
import signal
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = ROOT / "build" / "test-out" / "gui-wakeup.log"
sys.path.insert(0, str(ROOT / "tests"))
import process_lock_stress_test as harness  # noqa: E402


def qmp_quit(socket_path: Path) -> None:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    deadline = time.monotonic() + 5.0
    try:
        while True:
            try:
                connection.connect(str(socket_path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise harness.StressFailure("QMP socket did not become ready")
                time.sleep(0.05)
        stream = connection.makefile("rwb", buffering=0)
        if not stream.readline():
            raise harness.StressFailure("QMP closed before its greeting")
        for command in ({"execute": "qmp_capabilities"}, {"execute": "quit"}):
            stream.write(json.dumps(command).encode("ascii") + b"\r\n")
            while True:
                response = stream.readline()
                if not response:
                    if command["execute"] == "quit":
                        return
                    raise harness.StressFailure("QMP closed during handshake")
                decoded = json.loads(response)
                if "error" in decoded:
                    raise harness.StressFailure(f"QMP command failed: {decoded['error']}")
                if "return" in decoded:
                    break
    finally:
        connection.close()


def main() -> int:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("", encoding="utf-8")
    harness.LOG_PATH = LOG_PATH
    master_fd, slave_fd = pty.openpty()
    runner = None
    with tempfile.TemporaryDirectory(prefix="alix-gui-wakeup-") as temp_dir:
        temp = Path(temp_dir)
        qmp_path = temp / "qmp.sock"
        pid_path = temp / "qemu.pid"
        env = os.environ.copy()
        env.update(
            {
                "AUDIO_DEV": "none",
                "NETDUMP": "",
                "QEMU_DEBUG_FLAGS": "",
                "QEMU_GDB_FLAGS": f"-qmp unix:{qmp_path},server,nowait -pidfile {pid_path}",
                "QEMU_SERIAL_LOG": str(LOG_PATH),
                "QEMU_TIMEOUT_SECONDS": "55",
            }
        )
        try:
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

            harness.wait_for(runner, "login prompt", lambda text: "login:" in text, 30.0)
            harness.send_serial(master_fd, "root\r")
            harness.wait_for(runner, "password prompt", lambda text: "password:" in text, 5.0)
            harness.send_serial(master_fd, "root\r")
            harness.wait_for(runner, "shell prompt", lambda text: "root@alix$" in text, 10.0)

            start = len(harness.read_log())
            harness.send_serial(master_fd, "start_video\r")
            log = harness.wait_for(
                runner,
                "video loop on an idle AP",
                lambda text: (
                    "[thread_trampoline] start name=start_video" in text[start:]
                    and "video_run_loop start" in text[start:]
                ),
                15.0,
            )
            time.sleep(5.0)
            log = harness.read_log()
            if runner.poll() is not None:
                raise harness.StressFailure("QEMU exited after entering video mode")
            failure = harness.FAILURE_RE.search(log)
            if failure:
                raise harness.StressFailure(f"kernel failure marker found: {failure.group(0)!r}")
            if "video_run_loop end" in log[start:]:
                raise harness.StressFailure("video loop exited unexpectedly")

            qmp_quit(qmp_path)
            runner.wait(timeout=10.0)
            print("GUI wakeup test passed: start_video left its AP run queue and stayed live")
            print(f"serial log: {LOG_PATH}")
            return 0
        except (harness.StressFailure, subprocess.TimeoutExpired) as error:
            print(f"GUI wakeup test failed: {error}", file=sys.stderr)
            print(f"serial log: {LOG_PATH}", file=sys.stderr)
            return 1
        finally:
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


if __name__ == "__main__":
    raise SystemExit(main())
