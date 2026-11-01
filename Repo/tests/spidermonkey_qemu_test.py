#!/usr/bin/env python3
"""Execute the actual pinned upstream engine inside native Alix."""
from pathlib import Path
import argparse
import subprocess
import sys
sys.dont_write_bytecode=True
from cpp_runtime_qemu_test import run_native_elf
ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("timeout_seconds",nargs="?",type=int,default=180)
    parser.add_argument("--extended",action="store_true",help="also require native Ion JIT, GC, Wasm traps and worker atomics")
    options=parser.parse_args()
    subprocess.run(["make","-C","ports/zen/upstream/obj-js-alix","-j2"],cwd=ROOT,check=True)
    subprocess.run(["python3","ports/zen/prepare_native_js.py"],cwd=ROOT,check=True)
    # Encode the marker so shell command echo cannot satisfy execution proof.
    prefix="ALIX_SPIDERMONKEY: PASS value="
    code="print(String.fromCharCode("+",".join(str(ord(character)) for character in prefix)+")+6*7)"
    log=ROOT/"build/test-out/spidermonkey-basic-qemu.log"
    run_native_elf("spidermonkey_native.elf",("ALIX_SPIDERMONKEY: PASS value=42",),log,
                   "Real upstream SpiderMonkey",timeout_seconds=options.timeout_seconds,arguments=("-e",code),
                   forbidden_markers=("Assertion failure","MOZ_CRASH","uncaught exception"),download_timeout_seconds=120,
                   fail_on_missing_markers_at_exit=True,expected_wait_status=0)
    text=log.read_text(errors="replace")
    if text.count("ALIX_SPIDERMONKEY: PASS value=42")!=1:raise RuntimeError("engine marker was duplicated")
    if options.extended:
        markers=("ALIX_SPIDERMONKEY_RUNTIME: JIT PASS ion=1",
                 "ALIX_SPIDERMONKEY_RUNTIME: GC PASS roots=10000 cycles=8",
                 "ALIX_SPIDERMONKEY_RUNTIME: WASM PASS value=42 bounds_trap=1",
                 "ALIX_SPIDERMONKEY_RUNTIME: WORKER PASS shared_atomics=1")
        log=ROOT/"build/test-out/spidermonkey-runtime-qemu.log"
        run_native_elf("spidermonkey_native.elf",markers,log,"Upstream SpiderMonkey JIT/GC/Wasm/workers",
                       timeout_seconds=options.timeout_seconds,
                       arguments=("--ion-eager","--ion-offthread-compile=off","-f","/tmp/engine-runtime.js"),
                       forbidden_markers=("Assertion failure","MOZ_CRASH","uncaught exception"),
                       download_timeout_seconds=120,fail_on_missing_markers_at_exit=True,expected_wait_status=0,
                       input_files=(("engine-runtime.js",ROOT/"tests/spidermonkey_runtime_test.js"),))
        if any(log.read_text(errors="replace").count(marker)!=1 for marker in markers):
            raise RuntimeError("runtime execution marker was duplicated")
    return 0


if __name__=="__main__":
    try:sys.exit(main())
    except (OSError,RuntimeError,subprocess.SubprocessError) as error:
        print(f"Native SpiderMonkey failed: {error}",file=sys.stderr);sys.exit(1)
