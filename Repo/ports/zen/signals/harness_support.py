"""Pure evidence checks embedded in the pending native guest harness."""
from pathlib import Path
import re
import subprocess


def native_elf_symbol(binary, name):
    defined = subprocess.check_output(["x86_64-elf-nm", "--defined-only", str(binary)], text=True)
    values = {line.split()[2]: int(line.split()[0], 16)
              for line in defined.splitlines() if len(line.split()) == 3}
    if name not in values:
        raise RuntimeError("expected instruction symbol is absent from fixture ELF")
    return values[name]


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
