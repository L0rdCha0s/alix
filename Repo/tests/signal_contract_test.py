#!/usr/bin/env python3
"""Validate the shared native signal registry, frame ABI and ownership policy.
The former private libc callback-array test is replaced because signal()/raise()
now use kernel dispositions; the native tests/signal_test.c remains a regression
for 2048 calling-thread raises, persistent nested handlers and abort semantics.
"""
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
subprocess.run([sys.executable,str(ROOT/'ports/zen/signals/host_contract_test.py'),'--active'],check=True)
subprocess.run([sys.executable,str(ROOT/'ports/zen/signals/mapping_contract_test.py'),'--active'],check=True)
