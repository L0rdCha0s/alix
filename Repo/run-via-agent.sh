#!/usr/bin/env bash
set -euo pipefail

workdir="$(cd "$(dirname "$0")" && pwd)"
export WORKDIR="$workdir"

python3 - <<'PY'
import os, signal, subprocess, shlex
workdir = os.environ["WORKDIR"]
cmd = ["bash", "-lc", "cd " + shlex.quote(workdir) + " && NET_BACKEND=user make run-hdd"]
log_path = os.path.join(workdir, "qemu-serial.log")
with open(log_path, "w") as log:
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, preexec_fn=os.setsid)
    try:
        proc.wait(timeout=40)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=5)
PY
