#!/usr/bin/env bash
set -euo pipefail

workdir="$(cd "$(dirname "$0")" && pwd)"
export WORKDIR="$workdir"

python3 /dev/fd/3 3<<'PY'
import os, re, signal, subprocess, shlex, shutil, tempfile
from pathlib import Path
workdir = os.environ["WORKDIR"]
net_backend = os.environ.get("NET_BACKEND", "user")
data_img = os.environ.get("QEMU_DATA_IMG")
make_overrides = ""
if data_img:
    make_overrides = " DATA_IMG=" + shlex.quote(data_img)
cmd = [
    "bash",
    "-lc",
    "cd " + shlex.quote(workdir) +
    " && NET_BACKEND=" + shlex.quote(net_backend) +
    " make" + make_overrides + " run-hdd",
]
log_path = os.environ.get("QEMU_SERIAL_LOG", os.path.join(workdir, "qemu-serial.log"))
timeout_seconds = float(os.environ.get("QEMU_TIMEOUT_SECONDS", "40"))
with tempfile.TemporaryDirectory(prefix="alix-agent-boot-") as temporary:
    env = os.environ.copy()
    # Keep a private loader/kernel snapshot for this run so a concurrent build
    # cannot change the files QEMU reads. Caller-provided wrappers own theirs.
    external_qemu = env.get("QEMU") or re.search(r"(?:^|\s)QEMU=", env.get("MAKEFLAGS", ""))
    assignment = re.search(r"(?m)^QEMU\s*:?=\s*(.+)$", (Path(workdir) / "Makefile").read_text())
    if not external_qemu and assignment and "$" not in assignment.group(1):
        command = shlex.split(assignment.group(1))
        executable = shutil.which(command[0])
        if not executable:
            raise RuntimeError("QEMU executable is unavailable: " + command[0])
        command[0] = executable
        boot = Path(temporary) / "boot"
        wrapper = Path(temporary) / "qemu-boot"
        # Make invokes this only after building its run-hdd prerequisites.
        wrapper.write_text("#!/usr/bin/env python3\n"
            "import hashlib,os,shutil,sys\nfrom pathlib import Path\n"
            f"root=Path({workdir!r}); boot=Path({str(boot)!r})\n"
            f"command={command!r}\n"
            "args=sys.argv[1:]\n"
            "query=any(arg in ('--version','-version','--help','-help') for arg in args) or any(\n"
            " args[i] in ('-accel','-cpu','-machine','-device','-audiodev','-display') and args[i+1]=='help'\n"
            " for i in range(len(args)-1))\n"
            "if query: os.execv(command[0],command+args)\n"
            "(boot/'EFI/BOOT').mkdir(parents=True,exist_ok=True)\n"
            "shutil.copyfile(root/'build/alix.elf',boot/'alix.elf')\n"
            "shutil.copyfile(root/'build/EFI/BOOT/BOOTX64.EFI',boot/'EFI/BOOT/BOOTX64.EFI')\n"
            "print('[run-via-agent] boot kernel sha256='+hashlib.sha256((boot/'alix.elf').read_bytes()).hexdigest(),flush=True)\n"
            "if '-display' in args or '-nographic' in args:\n"
            " i=1; selected=[command[0]]\n"
            " while i<len(command):\n"
            "  if command[i]=='-display': i+=2\n"
            "  else: selected.append(command[i]); i+=1\n"
            " command=selected\n"
            f"args=[a.replace('file=fat:ro:build/boot,','file=fat:ro:{boot},') for a in args]\n"
            "os.execv(command[0],command+args)\n")
        wrapper.chmod(0o755)
        env["MAKEFLAGS"] = env.get("MAKEFLAGS", "") + " QEMU=" + str(wrapper)
    with open(log_path, "w") as log:
        proc = subprocess.Popen(cmd, env=env, stdout=log, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
        timed_out = False
        try:
            proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
        except BaseException:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=5)
            raise
        if proc.returncode and not timed_out:
            raise SystemExit(proc.returncode)
PY
