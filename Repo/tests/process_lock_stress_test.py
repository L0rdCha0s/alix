#!/usr/bin/env python3
"""Drive the SMP kernel's process/lock stress scenario through QEMU serial."""

from pathlib import Path
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
LOG_PATH = ROOT / "build" / "test-out" / "process-lock-stress.log"
FAILURE_RE = re.compile(
    r"process fatal:|paging panic:|quarantine thread=|stack guard violation|"
    r"ownership mismatch|switch_to_bad|context pointer corrupt|"
    r"\[sched\]\s+stall(?:\s|$)",
    re.IGNORECASE,
)


class StressFailure(RuntimeError):
    pass


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
            raise StressFailure(f"QEMU exited while waiting for {label}")
        time.sleep(0.05)
    raise StressFailure(f"timed out waiting for {label}")


def send_serial(master_fd: int, text: str) -> None:
    os.write(master_fd, text.encode("ascii"))


def qmp_ctrl_c(socket_path: Path) -> None:
    deadline = time.monotonic() + 5.0
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        while True:
            try:
                connection.connect(str(socket_path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    raise StressFailure("QMP socket did not become ready")
                time.sleep(0.05)
        stream = connection.makefile("rwb", buffering=0)
        greeting = stream.readline()
        if not greeting:
            raise StressFailure("QMP closed before its greeting")
        for command in (
            {"execute": "qmp_capabilities"},
            {
                "execute": "human-monitor-command",
                "arguments": {"command-line": "sendkey ctrl-c"},
            },
        ):
            stream.write(json.dumps(command).encode("ascii") + b"\r\n")
            while True:
                response = stream.readline()
                if not response:
                    raise StressFailure("QMP closed while sending Ctrl-C")
                decoded = json.loads(response)
                if "error" in decoded:
                    raise StressFailure(f"QMP command failed: {decoded['error']}")
                if "return" in decoded:
                    break
    finally:
        connection.close()


def stop_foreground_command(
    runner: subprocess.Popen[bytes], socket_path: Path, log_offset: int
) -> str:
    for _ in range(5):
        qmp_ctrl_c(socket_path)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            text = read_log()
            if "root@alix$" in text[log_offset:]:
                return text
            if runner.poll() is not None:
                raise StressFailure("QEMU exited while stopping letters")
            time.sleep(0.05)
    raise StressFailure("timed out waiting for prompt after Ctrl-C")


def stop_process(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def main() -> int:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Do not let markers from a previous run satisfy an early boot phase before
    # run-via-agent has opened and truncated the log itself.
    LOG_PATH.write_text("", encoding="utf-8")
    master_fd, slave_fd = pty.openpty()
    runner = None
    with tempfile.TemporaryDirectory(prefix="alix-lock-stress-") as temp_dir:
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
                "QEMU_TIMEOUT_SECONDS": "70",
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
            send_serial(master_fd, "root\r")
            wait_for(runner, "password prompt", lambda text: "password:" in text, 5.0)
            send_serial(master_fd, "root\r")
            wait_for(runner, "shell prompt", lambda text: "root@alix$" in text, 10.0)

            phase_start = len(read_log())
            send_serial(master_fd, "letters\r")
            wait_for(
                runner,
                "first detached letters child",
                lambda text: "<Child>" in text[phase_start:],
                10.0,
            )

            def sustained_churn(text: str) -> bool:
                phase = text[phase_start:]
                completed = phase.count("<EndChild>")
                destroyed = len(re.findall(r"\[proc\] destroy .*name=letters_child(?:\s|$)", phase))
                return completed >= 10 and destroyed >= 10

            churn_log = wait_for(runner, "sustained child completion/reaping", sustained_churn, 25.0)
            churn = churn_log[phase_start:]
            created = churn.count("<Child>")
            completed = churn.count("<EndChild>")
            destroyed = len(re.findall(r"\[proc\] destroy .*name=letters_child(?:\s|$)", churn))

            prompt_start = len(churn_log)
            stop_foreground_command(runner, qmp_path, prompt_start)

            top_start = len(read_log())
            send_serial(master_fd, "top\r")
            wait_for(
                runner,
                "top completion after stress",
                lambda text: (
                    "PID  STATE" in text[top_start:]
                    and re.search(r"\[proc\] destroy .*name=top(?:\s|$)", text[top_start:])
                    is not None
                ),
                10.0,
            )

            sentinel = "PROCESS_LOCK_STRESS_OK"
            echo_start = len(read_log())
            send_serial(master_fd, f"echo {sentinel}\r")
            wait_for(
                runner,
                "post-stress shell sentinel",
                lambda text: re.search(
                    rf"(?:^|\r?\n){sentinel}\r?\n", text[echo_start:], re.MULTILINE
                )
                is not None,
                10.0,
            )

            final_log = read_log()
            failure = FAILURE_RE.search(final_log)
            if failure:
                raise StressFailure(f"kernel failure marker found: {failure.group(0)!r}")

            send_serial(master_fd, "shutdown\r")
            try:
                runner.wait(timeout=15.0)
            except subprocess.TimeoutExpired as error:
                raise StressFailure("guest did not shut down") from error

            subprocess.run(
                [str(ROOT / "tests" / "process_smoke_test.sh"), str(LOG_PATH)],
                cwd=ROOT,
                check=True,
            )
            print(
                "process lock stress test passed: "
                f"created={created} completed={completed} destroyed={destroyed}; "
                "Ctrl-C, top, shell sentinel and shutdown remained responsive"
            )
            print(f"serial log: {LOG_PATH}")
            return 0
        except StressFailure as error:
            print(f"process lock stress test failed: {error}", file=sys.stderr)
            print(f"serial log: {LOG_PATH}", file=sys.stderr)
            return 1
        finally:
            if slave_fd >= 0:
                os.close(slave_fd)
            os.close(master_fd)
            if pid_path.exists():
                try:
                    stop_process(int(pid_path.read_text(encoding="ascii").strip()))
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
