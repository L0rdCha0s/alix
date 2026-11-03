#!/usr/bin/env python3
"""Install the real dl.sh font bundle and verify every file across a cold boot.

Run make first. All guest writes use a clone of data.img. Port 8000 must be
available, or --use-existing-server must point to the usual repository server.
"""

import argparse
import functools
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile

sys.dont_write_bytecode = True
from network_download_perf_test import Guest, Handler, Server, clone_file

ROOT = Path(__file__).resolve().parents[1]


class FontGuest(Guest):
    def command(self, command, timeout=300):
        offset = len(self.text())
        started = time.monotonic()
        marker = f"__FONT_PACKAGE_{time.monotonic_ns()}__"
        self.send(command + "\recho " + marker)
        # Echo's trailing newline can be separated from its marker by an SMP
        # serial log. A line-start marker still excludes echoed command input.
        pattern = re.compile(r"(?:^|[\r\n])" + re.escape(marker) + r"(?=[\r\n]|\[|$)")
        while time.monotonic() - started < timeout:
            text = self.text()[offset:]
            if pattern.search(text):
                return time.monotonic() - started, text
            if self.runner.poll() is not None:
                raise RuntimeError("font guest exited during: " + command)
            time.sleep(0.02)
        raise RuntimeError(f"timeout running {command!r}; inspect {self.log}")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def verify_fonts(guest, expected):
    for name, digest in expected.items():
        path = "/usr/share/fonts/" + name
        _, text = guest.command("sha1sum " + path)
        require(re.search(r"(?:^|[\r\n])" + digest + r"  " + re.escape(path) + r"(?:[\r\n]|$)", text),
                "installed font asset differs or is missing: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--use-existing-server", action="store_true")
    args = parser.parse_args()
    output = ROOT / "build/test-out/fonts-package"
    output.mkdir(parents=True, exist_ok=True)
    archive_path = ROOT / "build/fonts.zip"
    archive_data = archive_path.read_bytes()
    with zipfile.ZipFile(archive_path) as archive:
        require(archive.testzip() is None, "font archive CRC failure")
        manifest = json.loads(archive.read("manifest.json"))
        expected = {name: hashlib.sha1(archive.read(name)).hexdigest() for name in archive.namelist()}
        for entry in manifest["assets"]:
            require(hashlib.sha256(archive.read(entry["file"])).hexdigest() == entry["sha256"],
                    "font archive differs from its source manifest")
    server = guest = None
    requests = ["/build/user/runtime/unzip.elf", "/build/user/user-elfs.zip",
                "/build/wasm-demo.js", "/build/fonts.zip"]
    with tempfile.TemporaryDirectory(prefix="alix-font-package-") as temporary:
        temporary = Path(temporary)
        snapshot = temporary / "snapshot"
        (snapshot / "EFI/BOOT").mkdir(parents=True)
        shutil.copy2(ROOT / "build/alix.elf", snapshot / "alix.elf")
        shutil.copy2(ROOT / "build/EFI/BOOT/BOOTX64.EFI", snapshot / "EFI/BOOT/BOOTX64.EFI")
        if args.use_existing_server:
            # Read-only preflight: never stop or reconfigure the user's server.
            with urllib.request.urlopen("http://127.0.0.1:8000/build/fonts.zip", timeout=30) as response:
                require(response.read() == archive_data, "existing server is serving another font archive")
        else:
            http = snapshot / "http"
            for request in requests:
                path = Path(request.lstrip("/"))
                (http / path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / path, http / path)
            Handler.records = []
            server = Server(("127.0.0.1", 8000), functools.partial(Handler, directory=str(http)))
            threading.Thread(target=server.serve_forever, daemon=True).start()
        clone_file(ROOT / "data.img", temporary / "data.img")
        shutil.copy2(ROOT / "vendor/OVMF_VARS-1024x768.fd", temporary / "vars.fd")
        try:
            print("Installing system fonts with actual dl.sh in a private eight-CPU guest", flush=True)
            guest = FontGuest(temporary, snapshot, output, False, "install")
            # Force a fresh installation even if an older clone already has these fonts.
            for name in expected:
                guest.command("rm /usr/share/fonts/" + name)
            _, text = guest.command("/usr/bin/dl.sh", timeout=300)
            (output / "dl-install.log").write_text(text)
            if server:
                require([entry["path"] for entry in Handler.records] == requests,
                        "dl.sh fetched an unexpected package set")
            verify_fonts(guest, expected)
            guest.shutdown()
            guest.close()
            guest = None
            print("All installed font hashes match; checking a cold boot", flush=True)
            guest = FontGuest(temporary, snapshot, output, False, "reboot")
            verify_fonts(guest, expected)
            guest.shutdown()
            (output / "result.json").write_text(json.dumps({
                "cpus": 8, "font_files": sum("family" in a for a in manifest["assets"]),
                "verified_assets": len(expected), "cold_boot_persistence": True,
                "archive_sha256": hashlib.sha256(archive_data).hexdigest(),
                "kernel_sha256": hashlib.sha256((snapshot / "alix.elf").read_bytes()).hexdigest(),
                "installed_sha1": expected,
                "existing_http_server": args.use_existing_server,
            }, indent=2) + "\n")
        finally:
            if guest is not None:
                guest.close()
            if server:
                server.shutdown()
                server.server_close()
    print(f"System font installation/persistence: PASS; {len(expected)} assets; evidence in {output}")


if __name__ == "__main__":
    main()
