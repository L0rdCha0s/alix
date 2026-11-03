#!/usr/bin/env python3
"""Execute the native C++ startup test in an isolated, bounded Alix QEMU boot."""

from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import os
import re
import shlex
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
from quake_gui_liveness_test import QmpClient, move_mouse_to_terminal, hmp_send_keys

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


def native_elf_symbol(binary, name):
    defined = subprocess.check_output(["x86_64-elf-nm", "--defined-only", str(binary)], text=True)
    values = {line.split()[2]: int(line.split()[0], 16)
              for line in defined.splitlines() if len(line.split()) == 3}
    if name not in values:
        raise RuntimeError("expected instruction symbol is absent from fixture ELF")
    return values[name]


def start_user_breakpoint(qmp, staging, log_path, binary, definition):
    """Capture the actual guest call stack at a native user symbol, then detach."""
    symbol, symbols = definition[:2]
    extra_commands = "\n".join(definition[2]) if len(definition) > 2 else ""
    address = native_elf_symbol(binary, symbol)
    if native_elf_symbol(symbols, symbol) != address:
        raise RuntimeError("debug symbols do not match the native breakpoint address")
    debugger = shutil.which("x86_64-elf-gdb")
    if debugger is None:
        raise RuntimeError("native user breakpoint requires x86_64-elf-gdb")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    qmp.execute("stop")
    qmp.execute("human-monitor-command", {"command-line": f"gdbserver tcp:127.0.0.1:{port}"})
    script = staging / "user-breakpoint.gdb"
    output = log_path.with_suffix(".breakpoint.txt")
    script.write_text(f"""set pagination off
set auto-load off
set print elements 16
target remote 127.0.0.1:{port}
hbreak *{address}
commands
 silent
 echo ALIX_USER_BREAKPOINT_HIT\\n
{extra_commands}
 info registers rip rsp rbp rax rdi rsi rdx
 bt 32
 x/gx $rsp
 detach
 quit
end
echo ALIX_USER_BREAKPOINT_ARMED\\n
continue
""")
    with output.open("wb") as stream:
        process = subprocess.Popen([debugger, "-nx", "-q", "-batch", "-iex", "set auto-load off",
                                    "-x", str(script), str(symbols)],
                                   stdout=stream, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if "ALIX_USER_BREAKPOINT_ARMED" in output.read_text(errors="replace"):
            return process
        if process.poll() is not None:
            break
        time.sleep(0.05)
    process.terminate()
    process.wait(timeout=3)
    raise RuntimeError(f"could not arm native user breakpoint; see {output}")


def verify_expected_user_exception(phase, binary, expected):
    reason, symbol = expected
    records = re.findall(
        r"process: user fault in thread /tmp/test\.elf reason=([a-z_]+) "
        r"error=0x([0-9A-Fa-f]+) addr=0x([0-9A-Fa-f]+) "
        r"rip=0x([0-9A-Fa-f]+) cs=0x([0-9A-Fa-f]+) cpu=\d+", phase)
    if len(records) != 1 or phase.count("process: user fault") != 1:
        raise RuntimeError("incomplete expected user exception evidence")
    found, error, address, rip, cs = records[0]
    if found != reason or int(error, 16) != 0 or int(address, 16) != 0 or \
            int(rip, 16) != native_elf_symbol(binary, symbol) or (int(cs, 16) & 3) != 3:
        raise RuntimeError("user exception did not match the expected ELF instruction")


def verify_signal_termination(phase, binary, expected):
    marker, source, signo, status, vector, symbol = expected
    armed = re.findall(re.escape(marker) +
        r" pid=(\d+) tid=(\d+) signo=(\d+) status=(\d+) vector=(\d+) site=0x([0-9A-Fa-f]+)", phase)
    records = re.findall(
        r"process: default signal pid=(\d+) tid=(\d+) signo=(\d+) status=(\d+) "
        r"source=([a-z]+) vector=(\d+) rip=0x([0-9A-Fa-f]+)", phase)
    if len(armed) != 1 or len(records) != 1 or phase.count("process: default signal") != 1:
        raise RuntimeError("incomplete default-signal evidence")
    pid, tid, armed_signo, armed_status, armed_vector, armed_site = armed[0]
    found_pid, found_tid, found_signo, found_status, found_source, found_vector, found_rip = records[0]
    site = native_elf_symbol(binary, symbol) if symbol is not None else 0
    if (int(pid) <= 0 or int(tid) <= 0 or (pid, tid) != (found_pid, found_tid) or
        (int(armed_signo), int(armed_status), int(armed_vector), int(armed_site, 16)) != (signo, status, vector, site) or
        (int(found_signo), int(found_status), int(found_vector), int(found_rip, 16)) != (signo, status, vector, site) or
        found_source != source):
        raise RuntimeError("default signal did not match armed process, source, status, and instruction")
    if vector == 6:
        # The symbol itself must be the UD2, not a nearby unrelated exception.
        data = Path(binary).read_bytes()
        if data[:6] != b"\x7fELF\x02\x01":
            raise RuntimeError("expected a native little-endian ELF64 fixture")
        phoff = int.from_bytes(data[32:40], "little")
        size = int.from_bytes(data[54:56], "little")
        count = int.from_bytes(data[56:58], "little")
        opcode = None
        for index in range(count):
            header = data[phoff + index * size:phoff + (index + 1) * size]
            if int.from_bytes(header[:4], "little") != 1:
                continue
            offset = int.from_bytes(header[8:16], "little")
            virtual = int.from_bytes(header[16:24], "little")
            length = int.from_bytes(header[32:40], "little")
            if virtual <= site and site + 2 <= virtual + length:
                position = offset + site - virtual
                opcode = data[position:position + 2]
                break
        if opcode != b"\x0f\x0b":
            raise RuntimeError("expected invalid-opcode site is not UD2 in the actual ELF")


def capture_guest_failure(qmp, staging, log_path, user_binary=None, kernel_binary=None):
    """Retain stopped-guest evidence before the disposable VM is destroyed."""
    if qmp is None:
        return
    try:
        qmp.execute("stop")
        qmp.execute("screendump", {"filename": str(log_path.with_suffix(".failure.ppm").resolve())})
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
        user_globals = ""
        if user_binary is not None:
            for symbol in ("g_heap_lock", "g_env_mutex", "g_file_registry_lock"):
                try:
                    address = native_elf_symbol(user_binary, symbol)
                except RuntimeError:
                    continue
                user_globals += (
                    f"   if $alix_r->user_base <= {address} && {address} - $alix_r->user_base < $alix_r->mapped_size\n"
                    f'    printf "USER_GLOBAL {symbol} vaddr=0x%llX value=%u\\n", (unsigned long long){address}, '
                    f"*(unsigned int *)(0xffff800000000000 + $alix_r->phys_base + {address} - $alix_r->user_base)\n"
                    "   end\n")
        failure_elf = log_path.with_suffix(".kernel.elf")
        shutil.copyfile(kernel_binary or ROOT / "build/alix.elf", failure_elf)
        script.write_text(f"""set pagination off
set print elements 16
target remote 127.0.0.1:{port}
thread apply all info registers rip rsp rbp eflags
thread apply all bt 8
p g_ticks
p g_current_threads
p g_switch_out_threads
p g_run_queues
p g_scheduler_lock
p g_sleep_queue_lock
if g_vfs_service != 0
 p *g_vfs_service
 p *g_vfs_service->queue
 set $alix_worker = 0
 while $alix_worker < g_vfs_service->worker_count
  p g_vfs_service->workers[$alix_worker]
  set $alix_worker = $alix_worker + 1
 end
end
set $alix_t = g_thread_registry_head
set $alix_count = 0
set $alix_user_count = 0
while $alix_t != 0 && $alix_count < 256
 printf "THREAD %s state=%d cpu=%u queue=%d rqcpu=%u sleep=%d until=%llu depth=%u wake=%d transition=%d exited=%d\\n", $alix_t->name, $alix_t->state, $alix_t->running_cpu, $alix_t->in_run_queue, $alix_t->run_queue_cpu, $alix_t->sleeping, $alix_t->sleep_until_tick, $alix_t->preempt_disable_depth, $alix_t->wake_pending, $alix_t->in_transition, $alix_t->exited
 printf "  context=%p preempt=%d affinity=%d:%u lastcpu=%u pending_destroy=%d\\n", $alix_t->context, $alix_t->preempt_pending, $alix_t->affinity_enabled, $alix_t->affinity_cpu, $alix_t->last_cpu_index, $alix_t->pending_destroy
 if $alix_t->state == 1 && $alix_t->running_cpu == 4294967295 && !$alix_t->is_idle && !$alix_t->in_transition && $alix_t->context != 0
  printf "UNASSIGNED_RUNNING_CONTEXT\\n"
  x/20gx $alix_t->context
 end
 if $alix_t->is_user && $alix_user_count < 8
  printf "USER_SAVED pid=%llu tid=%llu resume=0x%llX context=%p\\n", $alix_t->owner_pid, $alix_t->tid, $alix_t->tls.preempt_resume_rip, $alix_t->context
  if $alix_t->io_request != 0
   p *$alix_t->io_request
  end
  if $alix_t->context != 0
   x/192gx $alix_t->context
  end
  set $alix_r = $alix_t->process->user_regions
  while $alix_r != 0
   printf "USER_REGION vaddr=0x%llX phys=0x%llX size=0x%llX\\n", $alix_r->user_base, $alix_r->phys_base, $alix_r->mapped_size
{user_globals}   set $alix_r = $alix_r->next
  end
  set $alix_user_count = $alix_user_count + 1
 end
 set $alix_t = $alix_t->registry_next
 set $alix_count = $alix_count + 1
end
detach
quit
""")
        result = subprocess.run([debugger, "-q", "-batch", "-x", str(script), str(failure_elf)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
        log_path.with_suffix(".gdb.txt").write_bytes(result.stdout)
    except Exception as error:
        log_path.with_suffix(".diagnostic-error.txt").write_text(str(error))


def run_native_elf(binary_name, markers, log_path, label, timeout_seconds=40,
                   arguments=(), expected_fault=None, tcg_cpu=None,
                   forbidden_markers=(), download_timeout_seconds=10, boot_markers=(),
                   expected_exception=None, expected_signal_termination=None, pcap_path=None,
                   fail_on_missing_markers_at_exit=False, expected_wait_status=None,
                   input_files=(), user_breakpoint=None, login_breakpoint=None, audio_capture_path=None,
                   gui_launch=False, after_breakpoint_commands=(), setup_commands=(),
                   disk_fixture=None, disk_snapshot=None):
    """Run a real target ELF, requiring its markers and successful shell return."""
    binary = ROOT / "build/user" / binary_name
    if user_breakpoint is not None and login_breakpoint is not None:
        raise RuntimeError("only one native debugger capture may be active")
    if after_breakpoint_commands and user_breakpoint is None:
        raise RuntimeError("post-breakpoint input requires a user breakpoint")
    if not binary.is_file():
        raise RuntimeError(f"build the native test first: {binary}")
    LOG = log_path
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text("")
    harness.LOG_PATH = LOG
    runner = qmp = server = uart = uart_reader = debugger_process = None
    audio_capturing = False
    stop_uart = threading.Event()
    with tempfile.TemporaryDirectory(prefix="alix-native-test-") as staging:
        staging = Path(staging)
        pidfile = staging / "qemu.pid"
        launch_log = staging / "launch.log"
        try:
            served = staging / "http"
            served.mkdir()
            shutil.copyfile(binary, served / "test.elf")
            for name, source in input_files:
                if name == "test.elf" or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name) is None:
                    raise RuntimeError("invalid native fixture input name")
                shutil.copyfile(source, served / name)
            if gui_launch:
                # The minimal boot disk deliberately omits installed apps.
                # Supply the freshly built terminal needed to launch the GUI
                # fixture, rather than depending on a stale disk installation.
                shutil.copyfile(ROOT / "build/user/atk_shell.elf", served / "__gui-terminal.elf")
            # Boot only the current main-tree kernel/loader. The complete build
            # directory includes debug artifacts and may exceed QEMU FAT16's
            # limit; copying also keeps the tested kernel and GDB symbols stable.
            boot = staging / "boot"
            (boot / "EFI/BOOT").mkdir(parents=True)
            kernel_image = boot / "alix.elf"
            shutil.copyfile(ROOT / "build/alix.elf", kernel_image)
            shutil.copyfile(ROOT / "build/EFI/BOOT/BOOTX64.EFI", boot / "EFI/BOOT/BOOTX64.EFI")
            def sha256(path):
                with Path(path).open("rb") as source:
                    return hashlib.file_digest(source, "sha256").hexdigest()
            boot_hashes = {"kernel_sha256": sha256(kernel_image),
                           "loader_sha256": sha256(boot / "EFI/BOOT/BOOTX64.EFI"),
                           "user_sha256": sha256(served / "test.elf")}
            if gui_launch:
                boot_hashes["gui_terminal_sha256"] = sha256(served / "__gui-terminal.elf")
            LOG.with_suffix(".boot-image.json").write_text(json.dumps(boot_hashes, indent=2) + "\n")
            real_qemu = shutil.which("qemu-system-x86_64")
            if real_qemu is None:
                raise RuntimeError("native fixture requires qemu-system-x86_64")
            wrapper = staging / "qemu-native-boot"
            wrapper.write_text("#!/usr/bin/env python3\nimport os,sys\n"
                "args=sys.argv[1:]\n"
                f"args=[a.replace('file=fat:ro:build/boot,','file=fat:ro:{boot},') for a in args]\n"
                f"os.execv({real_qemu!r},[{real_qemu!r}]+args)\n")
            wrapper.chmod(0o755)
            # Serve only this target binary over loopback.
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(
                QuietHandler, directory=str(served)))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            port = server.server_address[1]
            variables = staging / "vars.fd"
            shutil.copyfile(ROOT / "vendor/OVMF_VARS-1024x768.fd", variables)
            if disk_fixture is not None:
                shutil.copyfile(disk_fixture, staging / "data.img")
            env = os.environ.copy()
            env.update({
                "AUDIO_DEV": "none", "NETDUMP": "", "QEMU_DEBUG_FLAGS": "",
                "QEMU_GDB_FLAGS": f"-S -display none -qmp unix:{staging}/qmp.sock,server,nowait -pidfile {pidfile}",
                "QEMU_SERIAL": f"unix:{staging}/serial.sock,server,nowait",
                "QEMU_SERIAL_LOG": str(launch_log), "QEMU_TIMEOUT_SECONDS": str(timeout_seconds),
                "QEMU_DATA_IMG": str(staging / "data.img"),
                "OVMF_VARS": str(variables), "NET_BACKEND": "user",
            })
            env["MAKEFLAGS"] = env.get("MAKEFLAGS", "") + f" QEMU={wrapper} OVMF_VARS={variables} SMP_CORES=8"
            if audio_capture_path is not None:
                audio_capture_path = Path(audio_capture_path).resolve()
                audio_capture_path.parent.mkdir(parents=True, exist_ok=True)
                env["MAKEFLAGS"] += " HDA_AUDIO_ID=snd0"
            if pcap_path is not None:
                capture = Path(pcap_path).resolve()
                capture.parent.mkdir(parents=True, exist_ok=True)
                env["NETDUMP"] = "-object " + shlex.quote(
                    f"filter-dump,id=native_test_capture,netdev=n0,queue=all,file={capture}")
            if tcg_cpu is not None:
                env["QEMU_ACCEL"] = "tcg"
                env["TCG_CPU_TYPE"] = tcg_cpu
            runner = subprocess.Popen([str(ROOT / "run-via-agent.sh")], cwd=ROOT,
                env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                start_new_session=True)
            qmp = QmpClient(staging / "qmp.sock", timeout=25)
            if (sha256(ROOT / "build/alix.elf") != boot_hashes["kernel_sha256"] or
                sha256(ROOT / "build/EFI/BOOT/BOOTX64.EFI") != boot_hashes["loader_sha256"] or
                sha256(binary) != boot_hashes["user_sha256"]):
                raise RuntimeError("main-tree boot artifacts changed during launch; complete make before native acceptance")
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

            def boot_failed(log):
                return ": FAIL" in log or any(marker in log for marker in forbidden_markers)

            boot_log = harness.wait_for(
                runner, "serial login", lambda log: "login:" in log or boot_failed(log), 25)
            if boot_failed(boot_log):
                failures = [line for line in boot_log.splitlines()
                            if ": FAIL" in line or any(marker in line for marker in forbidden_markers)]
                raise RuntimeError("kernel boot acceptance failed: " + " | ".join(failures[-3:]))
            if boot_markers and not all(marker in boot_log for marker in boot_markers):
                raise RuntimeError("kernel boot acceptance did not complete successfully")
            if login_breakpoint is not None:
                debugger_process = start_user_breakpoint(qmp, staging, LOG, kernel_image, login_breakpoint)
            command("root")
            # Boot-time disk synchronization can occupy the shell's assigned
            # TCG CPU for several seconds while host compilers run in parallel.
            harness.wait_for(runner, "password", lambda log: "password:" in log, 15)
            command("root")
            harness.wait_for(runner, "shell", lambda log: "root@alix$" in log, 15)
            harness.wait_for(runner, "network/startup completion",
                lambda log: "dhcp: lease acquired." in log and
                            re.search(r"\[proc\] destroy[^\n]*name=startup", log), 15)
            for preparation, expected in setup_commands:
                offset = len(harness.read_log())
                command(preparation)
                prepared = harness.wait_for(runner, "disposable guest setup",
                    lambda log: command_complete(log, offset), 15)
                if expected not in prepared[offset:]:
                    raise RuntimeError("disposable guest setup failed: " + preparation)
            offset = len(harness.read_log())
            command("mkdir /tmp")
            harness.wait_for(runner, "tmp directory", lambda log: command_complete(log, offset), 3)
            offset = len(harness.read_log())
            command(f"wget http://10.0.2.2:{port}/test.elf /tmp/test.elf")
            harness.wait_for(runner, "test download", lambda log: command_complete(log, offset), download_timeout_seconds)
            for name, _ in input_files:
                offset = len(harness.read_log())
                command(f"wget http://10.0.2.2:{port}/{name} /tmp/{name}")
                harness.wait_for(runner, "fixture input download",
                    lambda log: command_complete(log, offset), download_timeout_seconds)
            offset = len(harness.read_log())
            launch = "/tmp/test.elf" if gui_launch else "runelf /tmp/test.elf"
            if arguments:
                launch += " " + " ".join(arguments)
            if gui_launch:
                for directory in ("/usr", "/usr/bin"):
                    preparation = len(harness.read_log())
                    command("mkdir " + directory)
                    harness.wait_for(runner, "GUI dependency directory",
                        lambda log: command_complete(log, preparation), 3)
                preparation = len(harness.read_log())
                command(f"wget http://10.0.2.2:{port}/__gui-terminal.elf /usr/bin/atk_shell.elf")
                harness.wait_for(runner, "fresh GUI terminal",
                    lambda log: command_complete(log, preparation), download_timeout_seconds)
                expected = f"Saved {(served / '__gui-terminal.elf').stat().st_size} bytes to /usr/bin/atk_shell.elf"
                if expected not in harness.read_log()[preparation:]:
                    raise RuntimeError("fresh GUI terminal was not installed in the disposable guest")
                offset = len(harness.read_log())
                command("start_video")
                harness.wait_for(runner, "video event loop", lambda log: "video_run_loop start" in log[offset:], 15)
                move_mouse_to_terminal(qmp)
                # USB polling must observe both edges even under eight-core
                # TCG scheduling; a short host tap can coalesce before polling.
                qmp.human("mouse_button 1")
                time.sleep(0.2)
                qmp.human("mouse_button 0")
                time.sleep(0.2)
                harness.wait_for(runner, "desktop terminal", lambda log: "start name=atk_shell" in log[offset:], 15)
                time.sleep(0.3)
                offset = len(harness.read_log())
            if user_breakpoint is not None:
                debugger_process = start_user_breakpoint(qmp, staging, LOG, binary, user_breakpoint)
            if audio_capture_path is not None:
                response = qmp.execute("human-monitor-command", {"command-line":
                    f"wavcapture {audio_capture_path} snd0 48000 16 2"})
                if not audio_capture_path.is_file():
                    raise RuntimeError(f"native audio capture did not start: {response}")
                audio_capturing = True
            if gui_launch:
                key_names = {" ": "spc", "/": "slash", ".": "dot", ":": "shift-semicolon",
                             "_": "shift-minus", "-": "minus"}
                hmp_send_keys(qmp, [key_names.get(char, char) for char in launch] + ["ret"])
            else:
                command(launch)

            breakpoint_actions_done = False

            def execution_complete(log):
                nonlocal breakpoint_actions_done
                if after_breakpoint_commands and not breakpoint_actions_done and debugger_process.poll() is not None:
                    capture = LOG.with_suffix(".breakpoint.txt").read_text(errors="replace")
                    if debugger_process.returncode != 0 or "ALIX_USER_BREAKPOINT_HIT" not in capture:
                        raise RuntimeError("native breakpoint did not complete before input injection")
                    # Input is sent after detach/resume. QEMU may ignore input
                    # queued through the debug monitor while vCPUs are stopped.
                    for action in after_breakpoint_commands:
                        response = qmp.human(action)
                        if response.strip():
                            raise RuntimeError(f"post-breakpoint command failed: {response}")
                    breakpoint_actions_done = True
                # Terminal redraws can publish prompt-shaped lines while QMP
                # is still typing a command. Completion requires the actual
                # fixture PID's retirement for console and GUI launches alike.
                phase = log[offset:]
                initial = re.search(r"\[process\] alloc detail[^\n]* name=/tmp/test\.elf pid=0x([0-9a-fA-F]+)", phase)
                return initial is not None and any(int(pid, 16) == int(initial.group(1), 16)
                    for pid in re.findall(r"\[proc\] destroy pid=0x([0-9a-fA-F]+) name=/tmp/test\.elf [^\n]* wait_status=\d+", phase))
            def fixture_complete(log):
                complete = execution_complete(log)
                return complete and (all(marker in log[offset:] for marker in markers) or
                                     ": FAIL" in log[offset:] or fail_on_missing_markers_at_exit)

            log = harness.wait_for(runner, label, fixture_complete, max(10, timeout_seconds - 20))
            phase = log[offset:]
            if not all(marker in phase for marker in markers) or ": FAIL" in phase:
                raise RuntimeError(f"{label} reported failure")
            if any(marker in phase for marker in forbidden_markers):
                raise RuntimeError(f"{label} continued past its expected termination point")
            if expected_wait_status is not None:
                launched = re.search(
                    r"\[process\] alloc detail[^\n]* name=/tmp/test\.elf pid=0x([0-9a-fA-F]+)", phase)
                if launched is None:
                    raise RuntimeError(f"{label} has no launched-process PID evidence")
                statuses = [status for pid, status in re.findall(
                    r"\[proc\] destroy pid=0x([0-9a-fA-F]+) name=/tmp/test\.elf [^\n]* wait_status=(\d+)", phase)
                    if int(pid, 16) == int(launched.group(1), 16)]
                if statuses != [str(expected_wait_status)]:
                    raise RuntimeError(f"{label} did not exit with wait status {expected_wait_status}: {statuses}")
            positions = [phase.index(marker) for marker in markers]
            if positions != sorted(positions):
                raise RuntimeError(f"{label} markers are out of order")
            if harness.FAILURE_RE.search(log):
                raise RuntimeError("kernel fault or scheduler failure in guest log")
            if expected_signal_termination is not None:
                verify_signal_termination(phase, binary, expected_signal_termination)
            if expected_exception is not None:
                verify_expected_user_exception(phase, binary, expected_exception)
                recovered = len(harness.read_log())
                command("echo fault_recovered")
                harness.wait_for(runner, "shell responds after expected user exception",
                    lambda text: re.search(r"(?:^|\n)fault_recovered\r?\n", text[recovered:]), 5)
            elif expected_fault is None:
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
            if audio_capturing:
                qmp.execute("human-monitor-command", {"command-line": "stopcapture 0"})
                audio_capturing = False
                if audio_capture_path.stat().st_size <= 44:
                    raise RuntimeError("native audio capture has no PCM frames")
            if disk_snapshot is not None:
                # Stop vCPUs before copying the private disk. No guest shutdown
                # or additional flush is issued: this preserves the state the
                # fixture itself committed, for a separate remount boot.
                qmp.execute("stop")
                shutil.copyfile(staging / "data.img", disk_snapshot)
            qmp.quit()
            runner.wait(timeout=8)
            if runner.returncode != 0:
                raise RuntimeError(f"runner failed with status {runner.returncode}")
            print(f"{label}: PASS in native Alix, 8-CPU QEMU guest")
            print(f"Serial evidence: {LOG}")
            return 0
        except Exception:
            if debugger_process is not None and debugger_process.poll() is None:
                debugger_process.terminate()
                debugger_process.wait(timeout=3)
            capture_guest_failure(qmp, staging, LOG,
                                  served / "test.elf" if "served" in locals() else binary,
                                  kernel_image if "kernel_image" in locals() else None)
            raise
        finally:
            if debugger_process is not None and debugger_process.poll() is None:
                debugger_process.terminate()
                debugger_process.wait(timeout=3)
            if qmp is not None:
                try:
                    if audio_capturing:
                        qmp.execute("human-monitor-command", {"command-line": "stopcapture 0"})
                    qmp.quit()
                except (RuntimeError, OSError):
                    pass
                qmp.close()
            # QMP quit can remove the pidfile between exists() and read().
            # A vanished file is normal after that owned VM exits; the runner
            # process group still has its independent cleanup below.
            try:
                qemu_pid = int(pidfile.read_text().strip())
            except FileNotFoundError:
                qemu_pid = None
            if qemu_pid is not None:
                harness.stop_process(qemu_pid)
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
