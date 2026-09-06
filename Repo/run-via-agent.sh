#!/usr/bin/env bash
set -euo pipefail

workdir="$(cd "$(dirname "$0")" && pwd)"
export WORKDIR="$workdir"

python3 /dev/fd/3 3<<'PY'
import os, signal, subprocess, shlex
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
with open(log_path, "w") as log:
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    try:
        proc.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
PY
