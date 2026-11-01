#!/usr/bin/env python3
"""Verify native descriptor readiness, SMP ownership and cancellation."""
from cpp_runtime_qemu_test import ROOT, run_native_elf
import socketserver
import threading
import time
import hashlib
import json


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        if self.request.recv(1) != b"G":
            raise RuntimeError("native poll client did not request data")
        time.sleep(0.05)
        self.request.sendall(bytes(index % 251 for index in range(16384)))

if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            run_native_elf("poll_test.elf",
                ("POLL_TEST: SMP PASS cpus=8", "POLL_TEST: TCP PASS bytes=16384 eof=1",
                 "POLL_TEST: PASS timeout=1 pipes=1 cpus=8 close_reuse=1 signal=1 killed_waiter=1"),
                ROOT / "build/test-out/poll-native-qemu.log", "native descriptor polling", 55,
                arguments=("tcp", str(server.server_address[1])),
                expected_wait_status=0, fail_on_missing_markers_at_exit=True,
                pcap_path=ROOT / "build/test-out/poll-native-network.pcap")
            log = ROOT / "build/test-out/poll-native-qemu.log"
            capture = ROOT / "build/test-out/poll-native-network.pcap"
            receipt = {"scope": "Targeted native polling smoke; NSPR, Gecko and Zen remain unverified",
                       "cpus": 8, "wait_status": 0,
                       "features": ["monotonic timeout", "pipe backpressure and hangup", "regular file",
                                    "8 CPU-pinned waiters", "16 KiB TCP data and EOF", "shared O_NONBLOCK status",
                                    "nonblocking TCP connect and idle read", "descriptor close/reuse",
                                    "caught signal EINTR", "killed waiter releases final pipe reader"],
                       "boot_images": json.loads(log.with_suffix(".boot-image.json").read_text()),
                       "log": str(log.relative_to(ROOT)), "capture": str(capture.relative_to(ROOT)),
                       "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest()}
            log.with_suffix(".acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n")
        finally:
            server.shutdown()
            thread.join(timeout=3)
