#!/usr/bin/env python3
"""Execute the native C++ startup test in an isolated, bounded Alix QEMU boot."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
import process_lock_stress_test as harness
from quake_gui_liveness_test import QmpClient

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "build/test-out/cpp-runtime-qemu.log"


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        pass


def type_command(qmp, text):
    keys = {" ": "spc", "/": "slash", ".": "dot", ":": "shift-semicolon",
            "_": "shift-minus", "-": "minus"}
    for key in [keys.get(char, char) for char in text] + ["ret"]:
        chord = key.split("-")
        # Explicit press/release avoids overlapping virtual-clock key-up
        # timers when eight TCG CPUs run slower than the host wall clock.
        qmp.execute("input-send-event", {"events": [
            {"type": "key", "data": {"down": True, "key": {"type": "qcode", "data": item}}}
            for item in chord]})
        time.sleep(0.12)
        qmp.execute("input-send-event", {"events": [
            {"type": "key", "data": {"down": False, "key": {"type": "qcode", "data": item}}}
            for item in reversed(chord)]})
        time.sleep(0.12)


def command_complete(log, offset):
    # Interactive line redraws also contain the prompt. Require a fresh line
    # after command output, so input cannot satisfy its own completion check.
    return re.search(r"(?:^|\n)root@alix\$ ", log[offset:]) is not None


def capture_guest_failure(qmp, staging, log_path):
    """Retain stopped-guest evidence before the disposable VM is destroyed."""
    if qmp is None:
        return
    try:
        qmp.execute("stop")
        details = []
        for command in ("info registers -a", "i /b 0x3fd"):
            details.append(command + "\n" + str(qmp.execute("human-monitor-command", {"command-line": command})))
        log_path.with_suffix(".registers.txt").write_text("\n\n".join(details))
        debugger = shutil.which("x86_64-elf-gdb")
        if debugger is None:
            return
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        qmp.execute("human-monitor-command", {"command-line": f"gdbserver tcp:127.0.0.1:{port}"})
        script = staging / "failure.gdb"
        script.write_text(f"""set pagination off
set print elements 16
target remote 127.0.0.1:{port}
thread apply all info registers rip rsp rbp eflags
thread apply all bt 8
p g_ticks
p g_current_threads
p g_scheduler_lock
p g_sleep_queue_lock
set $alix_t = g_thread_registry_head
while $alix_t != 0
 printf "THREAD %s state=%d cpu=%u queue=%d rqcpu=%u sleep=%d until=%llu depth=%u wake=%d transition=%d exited=%d\\n", $alix_t->name, $alix_t->state, $alix_t->running_cpu, $alix_t->in_run_queue, $alix_t->run_queue_cpu, $alix_t->sleeping, $alix_t->sleep_until_tick, $alix_t->preempt_disable_depth, $alix_t->wake_pending, $alix_t->in_transition, $alix_t->exited
 set $alix_t = $alix_t->registry_next
end
detach
quit
""")
        result = subprocess.run([debugger, "-q", "-batch", "-x", str(script), str(ROOT / "build/alix.elf")],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
        log_path.with_suffix(".gdb.txt").write_bytes(result.stdout)
    except Exception as error:
        log_path.with_suffix(".diagnostic-error.txt").write_text(str(error))


def run_native_elf(binary_name, markers, log_path, label, timeout_seconds=40,
                   arguments=(), expected_fault=None, tcg_cpu=None,
                   forbidden_markers=()):
    """Run a real target ELF, requiring its markers and successful shell return."""
    binary = ROOT / "build/user" / binary_name
    if not binary.is_file():
        raise RuntimeError(f"build the native test first: {binary}")
    LOG = log_path
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text("")
    harness.LOG_PATH = LOG
    runner = qmp = server = uart = uart_reader = None
    stop_uart = threading.Event()
    with tempfile.TemporaryDirectory(prefix="alix-native-test-") as staging:
        staging = Path(staging)
        pidfile = staging / "qemu.pid"
        launch_log = staging / "launch.log"
        try:
            served = staging / "http"
            served.mkdir()
            shutil.copyfile(binary, served / "test.elf")
            # Serve only this target binary over loopback.
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(
                QuietHandler, directory=str(served)))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            port = server.server_address[1]
            variables = staging / "vars.fd"
            shutil.copyfile(ROOT / "vendor/OVMF_VARS-1024x768.fd", variables)
            env = os.environ.copy()
            env.update({
                "AUDIO_DEV": "none", "NETDUMP": "", "QEMU_DEBUG_FLAGS": "",
                "QEMU_GDB_FLAGS": f"-S -qmp unix:{staging}/qmp.sock,server,nowait -pidfile {pidfile}",
                "QEMU_SERIAL": f"unix:{staging}/serial.sock,server,nowait",
                "QEMU_SERIAL_LOG": str(launch_log), "QEMU_TIMEOUT_SECONDS": str(timeout_seconds),
                "QEMU_DATA_IMG": str(staging / "data.img"),
                "OVMF_VARS": str(variables), "NET_BACKEND": "user",
            })
            if tcg_cpu is not None:
                env["QEMU_ACCEL"] = "tcg"
                env["TCG_CPU_TYPE"] = tcg_cpu
            runner = subprocess.Popen([str(ROOT / "run-via-agent.sh")], cwd=ROOT,
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True)
            qmp = QmpClient(staging / "qmp.sock", timeout=25)
            uart = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            uart.settimeout(0.5)
            uart.connect(str(staging / "serial.sock"))

            def collect_uart():
                with LOG.open("ab", buffering=0) as output:
                    while not stop_uart.is_set():
                        try:
                            data = uart.recv(65536)
                        except socket.timeout:
                            continue
                        except OSError:
                            break
                        if not data:
                            break
                        output.write(data)

            uart_reader = threading.Thread(target=collect_uart, daemon=True)
            uart_reader.start()
            # Connect before starting CPUs so early boot/SMP proof is retained.
            qmp.execute("cont")

            def command(text):
                uart.sendall(text.encode("ascii") + b"\r")

            harness.wait_for(runner, "serial login", lambda log: "login:" in log, 25)
            command("root")
            # Boot-time disk synchronization can occupy the shell's assigned
            # TCG CPU for several seconds while host compilers run in parallel.
            harness.wait_for(runner, "password", lambda log: "password:" in log, 15)
            command("root")
            harness.wait_for(runner, "shell", lambda log: "root@alix$" in log, 15)
            harness.wait_for(runner, "network/startup completion",
                lambda log: "dhcp: lease acquired." in log and
                            re.search(r"\[proc\] destroy[^\n]*name=startup", log), 15)
            offset = len(harness.read_log())
            command("mkdir /tmp")
            harness.wait_for(runner, "tmp directory", lambda log: command_complete(log, offset), 3)
            offset = len(harness.read_log())
            command(f"wget http://10.0.2.2:{port}/test.elf /tmp/test.elf")
            harness.wait_for(runner, "test download", lambda log: command_complete(log, offset), 10)
            offset = len(harness.read_log())
            launch = "runelf /tmp/test.elf"
            if arguments:
                launch += " " + " ".join(arguments)
            command(launch)
            log = harness.wait_for(runner, label,
                lambda log: (all(marker in log[offset:] for marker in markers) or
                             ": FAIL" in log[offset:]) and command_complete(log, offset),
                max(10, timeout_seconds - 20))
            phase = log[offset:]
            if not all(marker in phase for marker in markers) or ": FAIL" in phase:
                raise RuntimeError(f"{label} reported failure")
            if any(marker in phase for marker in forbidden_markers):
                raise RuntimeError(f"{label} continued past its expected termination point")
            positions = [phase.index(marker) for marker in markers]
            if positions != sorted(positions):
                raise RuntimeError(f"{label} markers are out of order")
            if harness.FAILURE_RE.search(log):
                raise RuntimeError("kernel fault or scheduler failure in guest log")
            if expected_fault is None:
                if ("=== CPU EXCEPTION ===" in log or "process: user fault" in log or
                        "process: fatal fault" in log):
                    raise RuntimeError("unexpected CPU exception in guest log")
            else:
                # Prove the intended user page fault, not an arbitrary crash.
                armed = re.search(r"(?:VM_FAULT_TEST|VM_ADVICE_FAULT): armed [a-z-]+ address=0x([0-9A-Fa-f]+)", phase)
                # Early emergency output is intentionally synchronous and may
                # interleave; this queued single-line snapshot is authoritative.
                records = re.findall(
                    r"process: user fault in thread /tmp/test\.elf reason=page_fault "
                    r"error=0x([0-9A-Fa-f]+) addr=0x([0-9A-Fa-f]+) "
                    r"rip=0x([0-9A-Fa-f]+) cs=0x([0-9A-Fa-f]+) cpu=\d+", phase)
                if not armed or len(records) != 1 or phase.count("process: user fault") != 1:
                    raise RuntimeError("incomplete hardware page-fault evidence")
                error, fault, rip, segment = (int(value, 16) for value in records[0])
                address = int(armed.group(1), 16)
                if fault != address or (error & 0x1F) != expected_fault or (segment & 3) != 3:
                    raise RuntimeError("page fault did not match requested protection")
                instruction = rip
                if expected_fault & 0x10:
                    if instruction != address:
                        raise RuntimeError("NX test did not fault at its generated-code address")
                else:
                    site = subprocess.check_output([
                        "x86_64-elf-addr2line", "-f", "-e", str(binary), hex(instruction)
                    ], text=True)
                    LOG.with_suffix(".fault-site.txt").write_text(site)
                    if Path(binary_name).stem + ".c:" not in site:
                        raise RuntimeError(f"unexpected fault site: {site}")
                recovered = len(harness.read_log())
                command("echo fault_recovered")
                harness.wait_for(runner, "shell still responds after user fault",
                    lambda text: re.search(r"(?:^|\n)fault_recovered\r?\n", text[recovered:]), 5)
            aps = len(re.findall(r"\[smp\] cpu online apic=", log))
            if aps != 7:
                raise RuntimeError(f"expected 8 CPUs; observed {aps} application processors")
            qmp.quit()
            runner.wait(timeout=8)
            if runner.returncode != 0:
                raise RuntimeError(f"runner failed with status {runner.returncode}")
            print(f"{label}: PASS in native Alix, 8-CPU QEMU guest")
            print(f"Serial evidence: {LOG}")
            return 0
        except Exception:
            capture_guest_failure(qmp, staging, LOG)
            raise
        finally:
            if qmp is not None:
                try:
                    qmp.quit()
                except (RuntimeError, OSError):
                    pass
                qmp.close()
            if pidfile.exists():
                harness.stop_process(int(pidfile.read_text().strip()))
            if runner is not None and runner.poll() is None:
                os.killpg(runner.pid, signal.SIGTERM)
                runner.wait(timeout=8)
            stop_uart.set()
            if uart is not None:
                uart.close()
            if uart_reader is not None:
                uart_reader.join(timeout=2)
            if launch_log.exists():
                LOG.with_suffix(".launch.log").write_bytes(launch_log.read_bytes())
            if server is not None:
                server.shutdown()
                server.server_close()


def main():
    return run_native_elf("cpp_runtime_test.elf",
        ("CPP_RUNTIME_TEST: main PASS", "CPP_RUNTIME_TEST: fini PASS"),
        LOG, "C++ runtime startup and ABI")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"C++ runtime QEMU test failed: {error}\nSerial evidence: {LOG}", file=sys.stderr)
        sys.exit(1)
