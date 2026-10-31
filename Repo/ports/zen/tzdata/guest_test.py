#!/usr/bin/env python3
"""Stage and execute the complete pinned timezone package in a disposable Alix guest."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/"tests"))
sys.dont_write_bytecode=True
from cpp_runtime_qemu_test import run_native_elf

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt",type=Path)
    parser.add_argument("--timeout",type=int,default=120)
    args=parser.parse_args()
    receipt=json.loads(args.receipt.read_text())
    binary=args.receipt.resolve().parent/(receipt["id"]+"-installer")/"tzdata_package_test.elf"
    run_native_elf(str(binary),(
        "TZDATA_CHECK: PASS",
        "TZDATA_STAGE: PASS",
        "TZDATA_VERIFY: PASS",
        "TZDATA_RUNTIME: PASS",
        "TZDATA_PACKAGE_TEST: PASS",
    ),ROOT/"build/test-out/tzdata-package-qemu.log","Complete pinned IANA package staging and runtime",args.timeout)

if __name__=="__main__":main()
