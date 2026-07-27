#!/usr/bin/env python3
"""Prove that boot-console login works through the emulated USB keyboard."""

from pathlib import Path
import os
import pty
import re
import signal
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
LOG_PATH = ROOT / "build" / "test-out" / "keyboard-boot-input.log"

sys.path.insert(0, str(ROOT / "tests"))
import process_lock_stress_test as harness  # noqa: E402
from quake_gui_liveness_test import QmpClient, hmp_send_keys  # noqa: E402


FAILURE_RE = re.compile(
    harness.FAILURE_RE.pattern + r"|=== CPU EXCEPTION ===",
    re.IGNORECASE,
)


def read_log() -> str:
    try:
        return LOG_PATH.read_bytes().decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def wait_for(runner: subprocess.Popen[bytes], label: str, predicate, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = read_log()
        if predicate(text):
            return text
        if runner.poll() is not None:
            raise harness.StressFailure(f"QEMU exited while waiting for {label}")
        time.sleep(0.05)
    raise harness.StressFailure(f"timed out waiting for {label}")


def main() -> int:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_PATH.write_text("", encoding="utf-8")

    master_fd, slave_fd = pty.openpty()
    runner = None
    qmp = None
    quit_sent = False
    with tempfile.TemporaryDirectory(prefix="alix-keyboard-boot-") as temp_dir:
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

            wait_for(runner, "login prompt", lambda text: "login:" in text, 30.0)
            qmp = QmpClient(qmp_path)

            qtree = qmp.human("info qtree")
            forbidden = re.search(r"\b(?:i8042|ps2-kbd)\b", qtree, re.IGNORECASE)
            if forbidden:
                raise harness.StressFailure(
                    "PS/2 keyboard path is present in QEMU qtree: "
                    f"{forbidden.group(0)}"
                )
            if not re.search(r"\busb-kbd\b", qtree, re.IGNORECASE):
                raise harness.StressFailure("USB keyboard is absent from QEMU qtree")

            password_start = len(read_log())
            hmp_send_keys(qmp, ["r", "o", "o", "t", "ret"])
            wait_for(
                runner,
                "password prompt after USB keyboard login",
                lambda text: "password:" in text[password_start:],
                8.0,
            )

            shell_start = len(read_log())
            hmp_send_keys(qmp, ["r", "o", "o", "t", "ret"])
            wait_for(
                runner,
                "shell prompt after USB keyboard password",
                lambda text: "root@alix$" in text[shell_start:],
                10.0,
            )

            sentinel_start = len(read_log())
            hmp_send_keys(
                qmp,
                [
                    "e",
                    "c",
                    "h",
                    "o",
                    "spc",
                    "k",
                    "e",
                    "y",
                    "b",
                    "o",
                    "a",
                    "r",
                    "d",
                    "shift-minus",
                    "b",
                    "o",
                    "o",
                    "t",
                    "shift-minus",
                    "o",
                    "k",
                    "ret",
                ],
            )
            final_log = wait_for(
                runner,
                "USB keyboard shell sentinel",
                lambda text: re.search(
                    r"(?:^|\r?\n)keyboard_boot_ok\r?\n",
                    text[sentinel_start:],
                    re.MULTILINE,
                )
                is not None,
                10.0,
            )

            failure = FAILURE_RE.search(final_log)
            if failure:
                raise harness.StressFailure(
                    f"kernel failure marker found: {failure.group(0)!r}"
                )

            qmp.quit()
            quit_sent = True
            qmp.close()
            qmp = None
            runner.wait(timeout=10.0)

            print(
                "keyboard boot input test passed: USB-only QMP keyboard "
                "completed login, password and shell sentinel"
            )
            print(f"serial log: {LOG_PATH}")
            return 0
        except (harness.StressFailure, subprocess.TimeoutExpired, OSError) as error:
            print(f"keyboard boot input test failed: {error}", file=sys.stderr)
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
                    harness.stop_process(
                        int(pid_path.read_text(encoding="ascii").strip())
                    )
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
