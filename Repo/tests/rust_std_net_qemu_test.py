#!/usr/bin/env python3
"""Real Rust std TCP, shared descriptor ownership and host packet readback."""
import errno
import socket
import socketserver
import threading
import time
from cpp_runtime_qemu_test import ROOT,run_native_elf

class Payload(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        if self.request.recv(1)!=b'G':raise RuntimeError('missing native Rust stream request')
        self.request.sendall(bytes(i%251 for i in range(64)))
        time.sleep(0.03)
        self.request.sendall(bytes(i%251 for i in range(64,32768)))

if __name__=='__main__':
    with socketserver.ThreadingTCPServer(('127.0.0.1',0),Payload) as server:
        server.daemon_threads=True
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1',0));refused=reservation.getsockname()[1]
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(('127.0.0.1',refused))!=errno.ECONNREFUSED:raise RuntimeError('host endpoint is not refused')
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            run_native_elf('rust_std_net_test.elf',
                ('RUST_STD_NET_TEST: PASS cpus=8 connections=9 bytes=294912 tcp=1 deadlines=1 fd_ownership=1 clone=1 cloexec=1 nonblock=1 peek=1 eof=1 lookup=1 hostname=1 capability_errors=1',),
                ROOT/'build/test-out/rust-std-net-qemu.log','Native Rust standard-library networking',140,
                arguments=(str(server.server_address[1]),str(refused)),expected_wait_status=0,
                fail_on_missing_markers_at_exit=True,pcap_path=ROOT/'build/test-out/rust-std-net-network.pcap')
        finally:server.shutdown();thread.join()
