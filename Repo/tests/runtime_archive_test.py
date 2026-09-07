#!/usr/bin/env python3
"""Verify that download ELFs retain the exact executable images and symbols."""

from collections import Counter
from pathlib import Path
import re
import struct
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
SYMBOL = struct.Struct("<IBBHQQ")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def slice_bytes(data, offset, size):
    require(offset <= len(data) and size <= len(data) - offset,
            "ELF table or payload is outside the file")
    return data[offset:offset + size]


def string_at(data, offset):
    require(offset < len(data), "ELF string offset is outside its table")
    end = data.find(b"\0", offset)
    require(end >= 0, "ELF string is not terminated")
    return data[offset:end]


def inspect_elf(data):
    require(len(data) >= ELF_HEADER.size, "ELF header is truncated")
    header = ELF_HEADER.unpack_from(data)
    require(header[0][:6] == b"\x7fELF\x02\x01", "expected a little-endian ELF64")
    require(header[9] == PROGRAM_HEADER.size and header[11] == SECTION_HEADER.size,
            "unexpected ELF table entry size")
    programs = list(PROGRAM_HEADER.iter_unpack(slice_bytes(
        data, header[5], header[10] * PROGRAM_HEADER.size)))
    sections = list(SECTION_HEADER.iter_unpack(slice_bytes(
        data, header[6], header[12] * SECTION_HEADER.size)))
    require(header[13] < len(sections), "section-name table is missing")
    strings = sections[header[13]]
    section_names = slice_bytes(data, strings[4], strings[5])
    names = {string_at(section_names, section[0]): section for section in sections}
    symbols = Counter()
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        require(section[6] < len(sections) and section[9] == SYMBOL.size,
                "invalid ELF symbol table")
        linked = sections[section[6]]
        strings = slice_bytes(data, linked[4], linked[5])
        for name, info, other, index, address, size in SYMBOL.iter_unpack(
                slice_bytes(data, section[4], section[5])):
            name = string_at(strings, name)
            # --strip-debug may drop STT_FILE records and renumber sections;
            # named runtime symbols must retain identity, binding and address.
            if name and info & 15 != 4:
                symbols[(name, info, other, address, size)] += 1
    loads = [(program, slice_bytes(data, program[2], program[5]))
             for program in programs if program[0] == 1]
    return {"entry": header[4], "programs": programs, "loads": loads,
            "sections": names, "symbols": symbols}


def verify_pair(original_data, runtime_data):
    original, runtime = inspect_elf(original_data), inspect_elf(runtime_data)
    require(original["entry"] == runtime["entry"], "ELF entry address changed")
    require(original["programs"] == runtime["programs"], "ELF program headers changed")
    require(original["loads"] == runtime["loads"], "ELF loaded bytes changed")
    require(original["symbols"] == runtime["symbols"], "ELF runtime symbols changed")
    require(b".debug_info" in original["sections"] and b".debug_line" in original["sections"],
            "original build ELF lost its source-level debugging information")
    require(b".symtab" in runtime["sections"], "runtime ELF lost its symbol table")
    require(not any(name.startswith((b".debug", b".zdebug"))
                    for name in runtime["sections"]), "runtime ELF still contains DWARF")
    require(len(runtime_data) < len(original_data), "runtime ELF did not shrink")
    return runtime


def expected_names():
    makefile = (ROOT / "Makefile").read_text()
    lines = makefile.splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith("USER_ELFS :="))
    value = lines[start]
    while lines[start].endswith("\\"):
        start += 1
        value += "\n" + lines[start]
    names = re.findall(r"\$\(USER_OBJDIR\)/([\w.-]+\.elf)", value)
    require(names and len(names) == len(set(names)), "USER_ELFS list is empty or duplicated")
    return names


def verify_negative_case(original, runtime, inspection):
    corrupt = bytearray(runtime)
    segment = next(program for program, payload in inspection["loads"] if payload)
    corrupt[segment[2]] ^= 1
    try:
        verify_pair(original, bytes(corrupt))
    except AssertionError as error:
        require(str(error) == "ELF loaded bytes changed", "corruption failed for the wrong reason")
    else:
        raise AssertionError("runtime verification accepted corrupt executable bytes")


def main():
    names = expected_names()
    directory = ROOT / "build/user"
    archive_path = directory / "user-elfs.zip"
    original_size = runtime_size = 0
    with zipfile.ZipFile(archive_path) as archive:
        require(Counter(archive.namelist()) == Counter(names),
                "archive has missing, stale, duplicate or renamed ELF entries")
        require(archive.testzip() is None, "archive CRC check failed")
        for index, name in enumerate(names):
            original_data = (directory / name).read_bytes()
            runtime_data = (directory / "runtime" / name).read_bytes()
            try:
                inspection = verify_pair(original_data, runtime_data)
                require(archive.read(name) == runtime_data, "archive contains another ELF variant")
                if index == 0:
                    verify_negative_case(original_data, runtime_data, inspection)
            except AssertionError as error:
                raise AssertionError(f"{name}: {error}") from error
            original_size += len(original_data)
            runtime_size += len(runtime_data)
    print(f"runtime archive test passed: {len(names)} ELFs, "
          f"{original_size} debug bytes -> {runtime_size} runtime bytes, "
          f"archive {archive_path.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError, struct.error, zipfile.BadZipFile) as error:
        print(f"runtime archive test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
