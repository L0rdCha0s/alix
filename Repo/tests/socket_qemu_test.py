#!/usr/bin/env python3
"""Verify native IPv4 TCP socket calls, including per-call flags on eight CPUs."""
from cpp_runtime_qemu_test import ROOT, run_native_elf
import socketserver
import socket
import subprocess
import re
import json
import hashlib
import errno
import threading
import time

class Payload(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        if self.request.recv(1) != b'G':
            raise RuntimeError('socket test did not request its payload')
        self.request.sendall(bytes(index % 251 for index in range(64)))
        time.sleep(0.03)
        self.request.sendall(bytes(index % 251 for index in range(64, 16384)))

if __name__ == '__main__':
    with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Payload) as server:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            refused_port = reservation.getsockname()[1]
        # A bound, non-listening Darwin socket silently drops SYNs. Close the
        # reservation and verify actual refusal before testing that error path.
        with socket.socket() as probe:
            probe.settimeout(1)
            if probe.connect_ex(('127.0.0.1', refused_port)) != errno.ECONNREFUSED:
                raise RuntimeError('host endpoint does not provide a refused-connect fixture')
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            run_native_elf('socket_test.elf',
                ('SOCKET_QUERY_TEST: PASS endpoints=1 options=1 failed_copy=1 error_once=1 cpus=8',
                 'SOCKET_TEST: PASS cpus=8 bytes=131072 blocking=1 nonblock=1 per_call=1 peek=1 aliases=1 eof=1 copy_checks=1'),
                ROOT / 'build/test-out/socket-native-qemu.log', 'native POSIX IPv4 TCP sockets', 120,
                arguments=(str(server.server_address[1]), str(refused_port)), expected_wait_status=0,
                fail_on_missing_markers_at_exit=True, pcap_path=ROOT / 'build/test-out/socket-native-network.pcap')
            log = ROOT / 'build/test-out/socket-native-qemu.log'
            capture = ROOT / 'build/test-out/socket-native-network.pcap'
            reported = re.findall(r'SOCKET_QUERY_ENDPOINT: cpu=(\d+) local=([\d.]+):(\d+) peer=([\d.]+):(\d+)', log.read_text())
            if len(reported) != 8 or {int(item[0]) for item in reported} != set(range(8)):
                raise RuntimeError('missing native endpoint query records')
            packets = subprocess.check_output(['tcpdump', '-nn', '-r', str(capture),
                'tcp[tcpflags] & tcp-syn != 0 and src host 10.0.2.15'], text=True, stderr=subprocess.STDOUT)
            log.with_suffix('.endpoints.pcap.txt').write_text(packets)
            observed = set(re.findall(r'IP ([\d.]+)\.(\d+) > ([\d.]+)\.(\d+):', packets))
            endpoints = {tuple(item[1:]) for item in reported}
            if len(endpoints) != 8 or not endpoints <= observed:
                raise RuntimeError('native endpoint metadata does not match TCP packets')
            receipt = {'scope': 'Targeted IPv4 TCP and query checks; complete sockets, NSPR/NSS, Gecko and Zen remain unverified',
                'cpus': 8, 'payload_bytes': 131072, 'endpoints_matched_to_capture': 8,
                'pending_error_once': True, 'failed_error_copy_preserved': True,
                'boot_images': json.loads(log.with_suffix('.boot-image.json').read_text()),
                'capture_sha256': hashlib.sha256(capture.read_bytes()).hexdigest()}
            log.with_suffix('.acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n')
        finally:
            server.shutdown()
            thread.join(timeout=3)
