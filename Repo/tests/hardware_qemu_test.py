#!/usr/bin/env python3
"""Bounded hardware-path acceptance with private firmware, boot files and disks."""
from pathlib import Path
import hashlib
import argparse
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from quake_gui_liveness_test import QmpClient

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build/test-out"


def type_command(qmp, text):
    keys = {" ": "spc", "_": "shift-minus", "-": "minus", "/": "slash", ".": "dot"}
    for char in list(text) + ["\n"]:
        chord = ("ret" if char == "\n" else keys.get(char, char)).split("-")
        qmp.execute("send-key", {"keys": [{"type": "qcode", "data": key} for key in chord], "hold-time": 30})
        time.sleep(.12)


def capture_failure(qmp, temp, log, kernel):
    if not qmp: return
    try:
        qmp.execute("stop")
        log.with_suffix(".registers.txt").write_text(str(qmp.execute("human-monitor-command", {"command-line": "info registers -a"})))
        exact = log.with_suffix(".kernel.elf")
        shutil.copyfile(kernel, exact)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        qmp.execute("human-monitor-command", {"command-line": f"gdbserver tcp:127.0.0.1:{port}"})
        script = temp / "failure.gdb"
        script.write_text(f"set pagination off\nset print elements 16\ntarget remote 127.0.0.1:{port}\nthread apply all bt 24\nthread apply all info registers rip rsp eflags\np g_ticks\np g_current_threads\np g_scheduler_lock\ndetach\nquit\n")
        result = subprocess.run(["x86_64-elf-gdb", "-nx", "-q", "-batch", "-x", str(script), str(exact)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
        log.with_suffix(".gdb.txt").write_bytes(result.stdout)
    except Exception as error:
        log.with_suffix(".diagnostic-error.txt").write_text(str(error))


def run_case(host="xhci", graphics="ramfb", serial=True, hub=False, usb_boot=False, memory="4G", cpus=8, *, kernel=None, loader=None):
    label = f"hardware-{host}-{graphics}" + ("" if serial else "-no-uart") + ("-hub" if hub else "") + ("-usb-boot" if usb_boot else "") + (f"-{memory}-{cpus}cpu" if memory != "4G" or cpus != 8 else "")
    log = OUT / (label + ".log")
    with tempfile.TemporaryDirectory(prefix="alix-hardware-") as folder:
        temp = Path(folder)
        boot = temp / "boot"
        (boot / "EFI/BOOT").mkdir(parents=True)
        shutil.copyfile(kernel or ROOT / "build/alix.elf", boot / "alix.elf")
        shutil.copyfile(loader or ROOT / "build/EFI/BOOT/BOOTX64.EFI", boot / "EFI/BOOT/BOOTX64.EFI")
        shutil.copyfile(ROOT / "vendor/OVMF_VARS-1024x768.fd", temp / "vars.fd")
        # A foreign disk on AHCI port 1 must survive boot byte-for-byte.
        foreign = temp / "foreign.img"
        with foreign.open("wb") as stream:
            stream.write(b"FOREIGN_DISK_DO_NOT_FORMAT" * 4096)
            stream.truncate(32 * 1024 * 1024)
        before = hashlib.sha256(foreign.read_bytes()).hexdigest()
        storage = temp / "usb.img"
        with storage.open("wb") as stream:
            stream.write(b"ALIX_USB_FIXTURE\0")
            stream.truncate(32 * 1024 * 1024)
        wrapper = temp / "qemu-wrapper"
        real_qemu = shutil.which("qemu-system-x86_64")
        wrapper.write_text(f'''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
for option in ("-display", "-monitor"):
    if option in args:
        i = args.index(option); args[i+1] = "none"
if "-vga" in args:
    i = args.index("-vga"); args[i+1] = {("none" if graphics == "ramfb" else "std")!r}
if {graphics == "ramfb"!r}: args += ["-device", "ramfb"]
if {not serial!r}:
    i = args.index("-serial"); args[i+1] = "none"
if {hub!r}:
    child = 0
    for i,arg in enumerate(args):
        if arg.startswith(("usb-kbd,", "usb-mouse,", "usb-storage,")):
            child += 1
            args[i] = arg.replace("bus=usbhost.0", "bus=usbhost.0,port=1." + str(child))
    i = args.index("qemu-xhci,id=usbhost")
    args[i+1:i+1] = ["-device", "usb-hub,id=testhub,bus=usbhost.0,port=1"]
if {usb_boot!r}:
    i = args.index("ide-hd,drive=fsdisk,bus=ahci0.0")
    args[i] = "usb-storage,bus=usbhost.0,drive=fsdisk,bootindex=1"
args = [arg.replace("file=fat:ro:build/boot", {("file=fat:ro:" + str(boot))!r}) for arg in args]
os.execv({real_qemu!r}, [{real_qemu!r}] + args)
''')
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env.update({"MAKEFLAGS": f"QEMU={wrapper}", "USB_HOST": host,
                    "RAM": memory, "SMP_CORES": str(cpus),
                    "USB_STORAGE_IMG": str(storage), "AUDIO_DEV": "none", "NET_BACKEND": "user",
                    "QEMU_ACCEL": "tcg", "OVMF_VARS": str(temp / "vars.fd"),
                    "QEMU_DATA_IMG": str(foreign), "QEMU_SERIAL_LOG": str(log),
                    "QEMU_TIMEOUT_SECONDS": "55", "QEMU_SERIAL": f"file:{OUT / (label + '.serial.log')}",
                    "QEMU_GDB_FLAGS": f"-qmp unix:{temp}/qmp.sock,server,nowait"})
        serial_log = OUT / (label + ".serial.log")
        runner = subprocess.Popen([str(ROOT / "run-via-agent.sh")], cwd=ROOT, env=env)
        qmp = None
        try:
            qmp = QmpClient(temp / "qmp.sock", timeout=25)
            def contents():
                return serial_log.read_text(errors="replace") if serial_log.exists() else ""
            def wait(marker, seconds=25):
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    text = contents()
                    if re.search(r"HARDWARE_USB_TEST: FAIL|CPU EXCEPTION|kernel panic", text):
                        raise RuntimeError(f"{label}: guest failure; see {serial_log}")
                    if marker in text: return
                    if runner.poll() is not None: break
                    time.sleep(.05)
                raise RuntimeError(f"{label}: missing {marker!r}; see {serial_log}")
            if serial:
                wait("HARDWARE_USB_TEST: PASS")
                wait("keyboard bound")
                wait("login:")
            else:
                time.sleep(8)
            type_command(qmp, "root")
            if serial: wait("password:", 5)
            else: time.sleep(.5)
            type_command(qmp, "root")
            if serial: wait("root@alix$", 20)
            else: time.sleep(.5)
            type_command(qmp, "echo hardware_keyboard_pass")
            if serial: wait("\nhardware_keyboard_pass\n", 5)
            type_command(qmp, "start_video")
            if serial: wait("video_run_loop start", 10)
            else: time.sleep(3)
            first = OUT / (label + ".ppm")
            qmp.execute("screendump", {"filename": str(first)})
            # The desktop has many colours. A text login/cursor blink cannot
            # satisfy the no-UART acceptance check through screen differences.
            pixels = first.read_bytes().split(b"\n", 3)[-1]
            if len({pixels[i:i+3] for i in range(0, len(pixels)-2, 3)}) < 16:
                raise RuntimeError(f"{label}: desktop is blank or still at text login")
            qmp.execute("input-send-event", {"events": [
                {"type": "rel", "data": {"axis": "x", "value": 125}},
                {"type": "rel", "data": {"axis": "y", "value": 80}}]})
            time.sleep(.5)
            second = OUT / (label + "-mouse.ppm")
            qmp.execute("screendump", {"filename": str(second)})
            if first.read_bytes() == second.read_bytes():
                raise RuntimeError(f"{label}: mouse did not change desktop screenshot")
            if serial and graphics == "ramfb": wait("[video] GOP framebuffer", 1)
            qmp.execute("quit")
            runner.wait(timeout=8)
            if hashlib.sha256(foreign.read_bytes()).hexdigest() != before:
                raise RuntimeError(f"{label}: foreign disk was modified")
            if serial:
                expected = bytes((i * 17 + 93) & 255 for i in range(512 * 33))
                with storage.open("rb") as stream:
                    stream.seek(40 * 512)
                    if stream.read(len(expected)) != expected: raise RuntimeError("USB writes did not reach backing disk")
            print(f"{label}: PASS keyboard, mouse, desktop, foreign disk preservation" + (", USB read/write/flush/ring wrap" if serial else ""), flush=True)
        except Exception:
            capture_failure(qmp, temp, serial_log, boot / "alix.elf")
            raise
        finally:
            if qmp:
                try: qmp.execute("quit")
                except (OSError, RuntimeError): pass
            if runner.poll() is None:
                runner.terminate()
                runner.wait(timeout=8)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", choices=("xhci", "uhci"), default="xhci")
    parser.add_argument("--graphics", choices=("ramfb", "std"), default="ramfb")
    parser.add_argument("--no-uart", action="store_true")
    parser.add_argument("--hub", action="store_true")
    parser.add_argument("--usb-boot", action="store_true")
    parser.add_argument("--memory", default="4G")
    parser.add_argument("--cpus", type=int, default=8)
    parser.add_argument("--matrix", action="store_true")
    options = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    subprocess.run(["make"], cwd=ROOT, check=True)
    # Separate output targets avoid timestamp-granularity races and never
    # install a self-test hook in the developer's ordinary kernel image.
    with tempfile.TemporaryDirectory(prefix="alix-hardware-artifacts-") as folder:
        kernel, loader = Path(folder) / "alix.elf", Path(folder) / "BOOTX64.EFI"
        subprocess.run(["make", "HARDWARE_SELFTEST=1", f"KERNEL_ELF={kernel}", f"EFI_BIN={loader}", str(kernel), str(loader)], cwd=ROOT, check=True)
        symbols = subprocess.check_output(["x86_64-elf-nm", "--defined-only", str(kernel)], text=True)
        if not re.search(r"\bT hardware_usb_boot_test$", symbols, re.M):
            raise RuntimeError("acceptance kernel does not contain its required test hook")
        if options.matrix:
            for case in (("xhci", "ramfb", True, False, False, "4G", 8),
                         ("xhci", "ramfb", True, True, False, "4G", 8),
                         ("xhci", "ramfb", False, False, False, "4G", 8),
                         ("uhci", "std", True, False, False, "4G", 8),
                         ("xhci", "ramfb", True, False, True, "8G", 1)):
                run_case(*case, kernel=kernel, loader=loader)
        else:
            run_case(options.host, options.graphics, not options.no_uart, options.hub, options.usb_boot, options.memory, options.cpus, kernel=kernel, loader=loader)
