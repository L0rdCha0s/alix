#!/usr/bin/env python3
"""Install the actual dl.sh bundle and execute its SpiderMonkey CLI in Alix.

Run make first. Uses a clone of data.img, private firmware/boot snapshots, and
run-via-agent.sh. The generated dl.sh requires local HTTP port 8000 to be free.
"""

import functools
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
from network_download_perf_test import Guest, Handler, Server, clone_file
from runtime_archive_test import verify_pair

ROOT = Path(__file__).resolve().parents[1]
CLI = "/usr/bin/js.elf"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def encoded_marker(prefix):
    # Command echo must not be sufficient execution evidence.
    return "String.fromCharCode(" + ",".join(str(ord(char)) for char in prefix) + ")"


def verify_exit(text, status):
    launches = re.findall(r"\[process\] alloc detail[^\r\n]* name=" + re.escape(CLI) +
                          r" pid=0x([0-9a-fA-F]+)", text)
    require(len(launches) == 1, "missing or duplicate native CLI launch")
    statuses = [int(value) for pid, value in re.findall(
        r"\[proc\] destroy pid=0x([0-9a-fA-F]+) name=" + re.escape(CLI) +
        r" [^\r\n]* wait_status=(\d+)", text) if int(pid, 16) == int(launches[0], 16)]
    require(statuses == [status], f"expected native CLI wait status {status}, got {statuses}")


def main():
    out = ROOT / "build/test-out/spidermonkey-package"
    out.mkdir(parents=True, exist_ok=True)
    runtime = ROOT / "build/user/runtime/js.elf"
    # Include upstream identity, not merely two copies of the package artifact.
    verify_pair((ROOT / "ports/zen/upstream/obj-js-alix/dist/bin/js").read_bytes(),
                runtime.read_bytes())
    digest = hashlib.sha1(runtime.read_bytes()).hexdigest()
    guest = None
    with tempfile.TemporaryDirectory(prefix="alix-js-package-") as temporary:
        temporary = Path(temporary)
        snapshot = temporary / "snapshot"
        (snapshot / "EFI/BOOT").mkdir(parents=True)
        http = snapshot / "http"
        (http / "build/user/runtime").mkdir(parents=True)
        shutil.copy2(ROOT / "build/alix.elf", snapshot / "alix.elf")
        shutil.copy2(ROOT / "build/EFI/BOOT/BOOTX64.EFI", snapshot / "EFI/BOOT/BOOTX64.EFI")
        shutil.copy2(ROOT / "build/user/user-elfs.zip", http / "build/user/user-elfs.zip")
        shutil.copy2(ROOT / "build/user/runtime/unzip.elf", http / "build/user/runtime/unzip.elf")
        shutil.copy2(ROOT / "tests/spidermonkey_runtime_test.js", http / "runtime.js")
        (http / "helper.js").write_text("function answer() { return 6 * 7; }\n")
        (http / "example.js").write_text(
            'load("/tmp/helper.js");\nassertEq(scriptArgs[0], "argument");\n'
            'print("ALIX_JS_PACKAGE: FILE PASS value=" + answer());\n')
        clone_file(ROOT / "data.img", temporary / "data.img")
        shutil.copy2(ROOT / "vendor/OVMF_VARS-1024x768.fd", temporary / "vars.fd")
        Handler.records = []
        server = Server(("127.0.0.1", 8000), functools.partial(Handler, directory=str(http)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            print("Installing actual dl.sh bundle in an isolated eight-CPU guest", flush=True)
            guest = Guest(temporary, snapshot, out, False, "install")
            _, text = guest.command("/usr/bin/dl.sh", timeout=300)
            (out / "dl-install.log").write_text(text)
            require([item["path"] for item in Handler.records] == [
                "/build/user/runtime/unzip.elf", "/build/user/user-elfs.zip"],
                "dl.sh did not use exactly the shipped bootstrap and archive")
            _, text = guest.command(f"sha1sum {CLI}")
            require(digest in text, "installed SpiderMonkey differs from the packaged runtime ELF")

            def execute(command, markers=(), status=0):
                _, text = guest.command(command, timeout=180)
                verify_exit(text, status)
                for marker in markers:
                    require(text.count(marker) == 1, f"missing or duplicated execution marker: {marker}")
                return text

            execute("js", ("The SpiderMonkey shell provides",))
            execute("js -e print(" + encoded_marker("ALIX_JS_PACKAGE: INLINE PASS value=") + "+6*7)",
                    ("ALIX_JS_PACKAGE: INLINE PASS value=42",))
            for name in ("helper.js", "example.js", "runtime.js"):
                guest.command(f"wget gateway:8000/{name} /tmp/{name}")
            execute("js /tmp/example.js argument", ("ALIX_JS_PACKAGE: FILE PASS value=42",))
            execute("js --ion-eager --ion-offthread-compile=off -f /tmp/runtime.js", (
                "ALIX_SPIDERMONKEY_RUNTIME: JIT PASS ion=1",
                "ALIX_SPIDERMONKEY_RUNTIME: GC PASS roots=10000 cycles=8",
                "ALIX_SPIDERMONKEY_RUNTIME: WASM PASS value=42 bounds_trap=1",
                "ALIX_SPIDERMONKEY_RUNTIME: WORKER PASS shared_atomics=1"))
            execute("js -e throw(42)", status=3 << 8)
            execute("js -e quit(7)", status=7 << 8)
            guest.shutdown()
            guest.close()
            guest = None
            # Prove that dl.sh placed the CLI on the persistent main volume.
            print("Cold-booting the cloned disk to verify persistent CLI execution", flush=True)
            guest = Guest(temporary, snapshot, out, False, "reboot")
            _, text = guest.command(f"sha1sum {CLI}")
            require(digest in text, "installed CLI changed across a cold boot")
            execute(CLI + " -e print(" + encoded_marker("ALIX_JS_PACKAGE: REBOOT PASS value=") + "+6*7)",
                    ("ALIX_JS_PACKAGE: REBOOT PASS value=42",))
            guest.shutdown()
            (out / "result.json").write_text(json.dumps({
                "cpus": 8, "installed_sha1": digest, "native_wait_status": 0,
                "features": ["dl.sh installation", "inline JS", "script/load/arguments",
                             "Ion JIT", "GC", "Wasm traps", "worker Atomics",
                             "runtime error status 3", "quit status 7", "cold-boot persistence"],
                "http_requests": [item["path"] for item in Handler.records],
            }, indent=2) + "\n")
        finally:
            if guest is not None:
                guest.close()
            server.shutdown()
            server.server_close()
    print(f"SpiderMonkey package: PASS; evidence in {out}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"SpiderMonkey package: FAIL: {error}", file=sys.stderr)
        sys.exit(1)
