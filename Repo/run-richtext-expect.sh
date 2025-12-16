#!/usr/bin/env expect
#
# Run QEMU via make run-hdd and automatically launch atk_richtext from the serial shell.
#
# Serial output is appended to `qemu-serial.log`.
#

set timeout 600

set workdir "/Users/alex/Documents/Projects/alix"
set net_backend "user"
if {[info exists ::env(NET_BACKEND)]} {
    set net_backend $::env(NET_BACKEND)
}
set cmd "cd $workdir && NET_BACKEND=$net_backend make run-hdd"

log_file -a "$workdir/qemu-serial.log"
log_user 0

if {[catch {spawn bash -lc $cmd} err]} {
    send_user "Failed to spawn QEMU: $err\n"
    exit 1
}

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

send "./atk_richtext\r"

# Watch for heap corruption or kernel exception after launch.
set timeout 120
expect {
    -re {\\[uheap\\] CORRUPTION} {
        catch { exec killall qemu-system-x86_64 }
        exit 2
    }
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

