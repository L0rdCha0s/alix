#!/usr/bin/env python3
"""Exercise native select readiness, safe copies and cancellation in Alix."""
import hashlib
import json
import socketserver
import threading
import time

from cpp_runtime_qemu_test import ROOT, run_native_elf


class Payload(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        if self.request.recv(1) != b"G":
            raise RuntimeError("native select client did not request data")
        time.sleep(0.05)
        self.request.sendall(bytes(i % 251 for i in range(16384)))


def main():
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Payload) as server:
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            log = ROOT / "build/test-out/select-native-qemu.log"
            capture = ROOT / "build/test-out/select-native-network.pcap"
            run_native_elf("select_test.elf",
                ("SELECT_TEST: SMP PASS cpus=8", "SELECT_TEST: TCP PASS bytes=16384 eof=1 except_hup=1",
                 "SELECT_TEST: PASS timeout=1 sets=1 cpus=8 close_reuse=1 signal=1 copy_checks=1 killed_waiter=1"),
                log, "native descriptor selection", 70,
                arguments=("tcp", str(server.server_address[1])),
                expected_wait_status=0, fail_on_missing_markers_at_exit=True,
                pcap_path=capture)
            receipt = {
                "scope": "Native select boundary; full NSPR, Gecko and Zen remain unverified",
                "cpus": 8, "wait_status": 0, "fd_set_bytes": 32, "fd_setsize": 256,
                "features": ["all descriptor bits", "sum readiness across sets", "highest descriptor",
                             "monotonic rounded timeout", "timeout unchanged", "safe input/output copies",
                             "8 CPU-pinned waiters", "16 KiB TCP data and EOF", "hangup is not exceptional",
                             "close/reuse", "signal EINTR", "killed waiter releases final reader"],
                "boot_images": json.loads(log.with_suffix(".boot-image.json").read_text()),
                "capture_sha256": hashlib.sha256(capture.read_bytes()).hexdigest(),
            }
            log.with_suffix(".acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n")
        finally:
            server.shutdown()
            thread.join(timeout=3)


if __name__ == "__main__":
    main()
