#!/usr/bin/env bash
set -euo pipefail

log_path="${1:-qemu-serial.log}"

if [[ ! -f "$log_path" ]]; then
    echo "process smoke test: missing log: $log_path" >&2
    exit 1
fi

online_aps="$(grep -c '\[smp\] cpu online apic=' "$log_path" || true)"
if [[ "$online_aps" -ne 7 ]]; then
    echo "process smoke test: expected 7 application CPUs online, got $online_aps" >&2
    exit 1
fi

if ! grep -Fq 'login:' "$log_path"; then
    echo "process smoke test: login prompt was not reached" >&2
    exit 1
fi

for process_name in hda_init dhclient ntpdate startup
do
    if ! grep -Eq "\[proc\] destroy .*name=${process_name}([[:space:]]|$)" "$log_path"; then
        echo "process smoke test: missing teardown for $process_name" >&2
        exit 1
    fi
done

failure_pattern='process fatal:|paging panic:|quarantine thread=|stack guard violation|ownership mismatch|switch_to_bad|context pointer corrupt|\[sched\][[:space:]]+stall([[:space:]]|$)'
if grep -Eqi "$failure_pattern" "$log_path"; then
    echo "process smoke test: scheduler/process failure marker found" >&2
    grep -Ein "$failure_pattern" "$log_path" >&2
    exit 1
fi

echo "process smoke test passed: 8 CPUs, login reached, lifecycle teardown clean"
