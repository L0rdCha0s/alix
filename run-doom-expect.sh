#!/usr/bin/env expect
#
# Run QEMU via make run-hdd and automatically launch Doom from the serial shell.
#
# This is meant for debugging: it waits for the shell prompt, then follows
# the host-sync workflow:
#   1) wait 5s after boot
#   2) cd /usr/bin
#   3) run ./dl.sh to pull latest doom bits
#   4) wait 10s for transfer
#   5) run ./doom.elf

# Default timeout (in seconds). Under TCG, guest time runs much slower than
# wall-clock, so keep this fairly high for long-run stability tests.
set timeout 600

set workdir "/Users/alex/Documents/Projects/alix"
set net_backend "user"
if {[info exists ::env(NET_BACKEND)]} {
    set net_backend $::env(NET_BACKEND)
}
set cmd "cd $workdir && NET_BACKEND=$net_backend make run-hdd"

log_file -a "$workdir/qemu-serial.log"
# Don't spam stdout; the serial log above is the source of truth.
log_user 0

if {[catch {spawn bash -lc $cmd} err]} {
    send_user "Failed to spawn QEMU: $err\n"
    exit 1
}

# Wait for the shell to come up (best-effort; logs can interleave).
set timeout 30
expect {
    -re {In-memory FS shell ready} { }
    timeout { }
}

# Step 1: wait a bit after boot for services.
after 5000

# Nudge the shell to print a prompt even if stdout is buffered.
catch { send "\r" }
set timeout 5
expect {
    -re {alex@alix\\$} { }
    timeout { }
}

# Step 2: cd into /usr/bin.
send "cd /usr/bin\r"
set timeout 10
expect {
    -re {alex@alix\\$} { }
    timeout { }
}

# Step 3: download latest doom build/files.
send "./dl.sh\r"

# Step 4: give the download time to complete.
after 10000

# Step 5: launch doom.
set doom_args ""
if {[info exists ::env(DOOM_ARGS)]} {
    set doom_args $::env(DOOM_ARGS)
}
send "./doom.elf $doom_args\r"

# Let it run; restore the outer timeout (previous expects set shorter timeouts).
set timeout 600
expect {
    timeout { }
}

# Attempt a clean shutdown if we still have control.
catch { send "shutdown\r" }
# QEMU may already have exited (e.g. guest panic / triple fault).
catch { expect eof }
