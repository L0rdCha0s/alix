#!/usr/bin/env python3
"""Run actual Socket2 calls over real guest/host TCP connections."""
import errno
import socket
import socketserver
import threading
import time
from cpp_runtime_qemu_test import ROOT, run_native_elf

class Payload(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        request = b""
        while len(request) < 3:
            data = self.request.recv(3 - len(request))
            if not data:
                raise RuntimeError("short Socket2 gather request")
            request += data
        if request != b"GET":
            raise RuntimeError("invalid Socket2 gather request")
        self.request.sendall(bytes(i % 251 for i in range(64)))
        time.sleep(0.03)
        self.request.sendall(bytes(i % 251 for i in range(64, 32768)))

if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Payload) as server:
        server.daemon_threads = True
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            refused = reservation.getsockname()[1]
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(("127.0.0.1", refused)) != errno.ECONNREFUSED:
                raise RuntimeError("host Socket2 refusal fixture unavailable")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            run_native_elf("rust_socket2_test.elf", (
                "RUST_SOCKET2_TEST: PASS cpus=8 connections=9 bytes=294912 all_feature=1 tcp=1 deadlines=1 clone=1 fd_ownership=1 cloexec=1 nonblock=1 peek=1 eof=1 c_abi=1 gather=1 scatter=1 message_faults=1 capability_errors=1",
            ), ROOT / "build/test-out/rust-socket2-qemu.log", "Native Gecko Socket2 TCP", 140,
                arguments=(str(server.server_address[1]), str(refused)), expected_wait_status=0,
                fail_on_missing_markers_at_exit=True,
                pcap_path=ROOT / "build/test-out/rust-socket2-network.pcap")
        finally:
            server.shutdown()
            thread.join()
