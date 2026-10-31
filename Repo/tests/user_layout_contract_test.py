#!/usr/bin/env python3
"""Compare active C and both ELF linker layout contracts and overlap guards."""
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/"ports/zen/layout"))
import check_pending as contract

contract.PENDING=ROOT
with tempfile.TemporaryDirectory(prefix="alix-layout-contract-") as temporary:
    contract.linker_contract(Path(temporary))
