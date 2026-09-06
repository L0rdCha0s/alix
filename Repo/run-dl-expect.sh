#!/usr/bin/env expect
#
# Run QEMU via make run-hdd and refresh user binaries from the serial shell.
#
# This is meant for debugging: it waits for the shell prompt, then follows
# the host-sync workflow:
#   1) log in as the development root user
#   2) cd /usr/bin
#   3) run ./dl.sh to pull the compressed user-binary bundle
#   4) wait for extraction to complete

# Default timeout (in seconds). Under TCG, guest time runs much slower than
# wall-clock, so keep this fairly high for long-run stability tests.
set timeout 600

set script_path [file normalize [info script]]
set workdir [file dirname $script_path]
set net_backend "user"
if {[info exists ::env(NET_BACKEND)]} {
    set net_backend $::env(NET_BACKEND)
}
set cmd "cd $workdir && NET_BACKEND=$net_backend make run-hdd"

set serial_log "$workdir/qemu-serial.log"
if {[info exists ::env(QEMU_SERIAL_LOG)]} {
    set serial_log $::env(QEMU_SERIAL_LOG)
}
log_file -a $serial_log
# Don't spam stdout; the serial log above is the source of truth.
log_user 0

if {[catch {spawn bash -lc $cmd} err]} {
    send_user "Failed to spawn QEMU: $err\n"
    exit 1
}

# Step 1: log in after startup networking has completed.
set timeout 30
expect -re {login:}
send "root\r"
expect -re {password:}
send "root\r"
expect -re {root@alix\$}

# Step 2: cd into /usr/bin.
send "cd /usr/bin\r"
set timeout 10
expect -re {root@alix\$}

# Step 3: download latest doom build/files.
send "./dl.sh\r"

# Step 4: wait for the archive extractor to finish.
set timeout 120
expect -re {unzip: done}
set timeout 30
expect -re {root@alix\$}

# Attempt a clean shutdown if we still have control.
catch { send "shutdown\r" }
# QEMU may already have exited (e.g. guest panic / triple fault).
catch { expect eof }
