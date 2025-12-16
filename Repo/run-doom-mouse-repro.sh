#!/usr/bin/env expect
#
# Reproduce the Doom "crash on mouse move" by injecting a mouse event via QMP/HMP.
#
# This spawns `make run-hdd` with a QMP unix socket, boots Alix, runs Doom from
# the serial shell, then sends `mouse_move` through QMP's human-monitor-command.
#
# Serial output is appended to `qemu-serial.log`.
#

set timeout 600

set workdir "/Users/alex/Documents/Projects/alix"
set qmp_sock "$workdir/qmp.sock"

catch { exec rm -f $qmp_sock }

# Use slirp networking so we don't need socket_vmnet wrapper in this harness.
set net_backend "user"
if {[info exists ::env(NET_BACKEND)]} {
    set net_backend $::env(NET_BACKEND)
}
set cmd "cd $workdir && NET_BACKEND=$net_backend QEMU_GDB_FLAGS='-qmp unix:$qmp_sock,server,nowait' make run-hdd"

log_file -a "$workdir/qemu-serial.log"
log_user 0

if {[catch {spawn bash -lc $cmd} err]} {
    send_user "Failed to spawn QEMU: $err\n"
    exit 1
}

# Wait for the shell prompt.
set timeout 30
expect {
    -re {In-memory FS shell ready} { }
    timeout { }
}

after 5000
catch { send "\r" }
set timeout 10
expect {
    -re {alex@alix\\$} { }
    timeout { }
}

send "cd /usr/bin\r"
set timeout 10
expect {
    -re {alex@alix\\$} { }
    timeout { }
}

# Launch doom.
send "./doom.elf\r"

# Wait until the window is opened (best-effort).
set timeout 120
expect {
    -re {\\[doom\\]\\[video\\] window_open ok} { }
    timeout { }
}

# Give QMP a moment to come up.
after 1500

# Inject a small mouse movement via QMP (HMP passthrough).
catch {
    exec python3 - <<PY
import json, os, socket, time

sock_path = r"$qmp_sock"

def qmp_recv_line(s):
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf

def qmp_send(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode("utf-8"))

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
for _ in range(200):
    if os.path.exists(sock_path):
        break
    time.sleep(0.05)
s.connect(sock_path)

# Greeting.
qmp_recv_line(s)
qmp_send(s, {"execute": "qmp_capabilities"})
qmp_recv_line(s)

# Move far enough to guarantee we enter the Doom window (likely centered).
for cmd in (
    "mouse_move 800 450",
    "mouse_move 10 0",
    "mouse_move 0 10",
    "mouse_move -5 -5",
):
    qmp_send(s, {"execute": "human-monitor-command", "arguments": {"command-line": cmd}})
    qmp_recv_line(s)
s.close()
PY
}

# Watch for the crash banner.
set timeout 120
expect {
    -re {=== CPU EXCEPTION ===} {
        catch { exec killall qemu-system-x86_64 }
        exit 2
    }
    timeout {
        catch { exec killall qemu-system-x86_64 }
        exit 0
    }
    eof {
        exit 0
    }
}
