#!/usr/bin/env python3
"""Verify owned TCP pool lifetime, then legacy download and TLS on eight CPUs."""
import os
import re
from pathlib import Path
import subprocess
import sys
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.dont_write_bytecode = True
from cpp_runtime_qemu_test import run_native_elf

ROOT = Path(__file__).resolve().parents[1]

def verify_capture(path, port):
    result = subprocess.run(['tcpdump', '-nn', '-tt', '-S', '-r', str(path), 'tcp', 'port', str(port)],
                            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    (ROOT / 'build/ports/zen/tcp-owned-connection-packets.txt').write_text(result.stdout)
    packets = []
    for line in result.stdout.splitlines():
        match = re.match(r'^\S+ IP (\S+) > (\S+): Flags \[([^]]+)\], (.*)$', line)
        if match: packets.append(match.groups())
    connections = {(packet[0], packet[1]) for packet in packets if packet[2] == 'S'}
    if len(connections) != 5: raise RuntimeError(f'expected five owned/event connections, captured {len(connections)}')
    payload_connections = sum(verify_connection(packets, guest, host) for guest, host in connections)
    if payload_connections != 2: raise RuntimeError('expected two complete 16 KiB HTTP response streams')
    print('Owned/event TCP packet acceptance PASS: connections=5 HTTP=2 bidirectional_FIN_ACK=5')

def verify_connection(packets, guest, host):
    if not any(src == host and dst == guest and flags == 'S.' for src, dst, flags, _ in packets):
        raise RuntimeError('owned connection has no captured SYN/ACK')
    fins = {}
    ranges = []
    for src, dst, flags, rest in packets:
        seq = re.search(r'\bseq (\d+)(?::(\d+))?', rest)
        length = re.search(r'\blength (\d+)', rest)
        count = int(length[1]) if length else 0
        if src == host and dst == guest and count and seq:
            first = int(seq[1]); last = int(seq[2]) if seq[2] else first + count
            if last - first != count: raise RuntimeError('capture payload sequence length mismatch')
            ranges.append((first, last))
        if 'F' in flags and seq and (src, dst) in ((guest, host), (host, guest)):
            fins[src] = int(seq[1]) + count + 1
    if guest not in fins or host not in fins:
        raise RuntimeError('owned connection did not complete both FIN directions')
    for source, destination in ((guest, host), (host, guest)):
        if not any(src == destination and dst == source and
                   (ack := re.search(r'\back (\d+)', rest)) and int(ack[1]) >= fins[source]
                   for src, dst, _, rest in packets):
            raise RuntimeError('owned connection FIN was not acknowledged')
    if not ranges: return 0  # Idle readers were canceled before sending HTTP.
    ranges.sort(); first, last = ranges[0]
    for start, end in ranges[1:]:
        if start > last: raise RuntimeError('gap in owned response sequence ranges')
        last = max(last, end)
    if last - first < 16384: raise RuntimeError('owned captured response is incomplete')
    return 1

def main():
    previous = os.environ.get('IO_TCP_SELFTEST')
    previous_port = os.environ.get('TCP_TEST_PORT')
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args): pass
        def do_GET(self):
            if self.path not in ('/owned', '/event'):
                self.send_error(404); return
            requests.append(self.path)
            body = bytes((index * 73 + 19) & 255 for index in range(16384))
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        os.environ['IO_TCP_SELFTEST'] = '1'
        os.environ['TCP_TEST_PORT'] = str(server.server_port)
        subprocess.run(['make', '-W', 'src/kernel/kernel.c', '-W', 'tests/tcp_owned_boot_test.c',
                        '-W', 'tests/io_event_tcp_boot_test.c', 'all', 'IO_TCP_SELFTEST=1',
                        'build/user/thread_tls_test.elf'], cwd=ROOT, check=True)
        run_native_elf('thread_tls_test.elf', ('THREAD_TLS_TEST: PASS',),
                       ROOT / 'build/test-out/tcp-owned-qemu.log',
                       'Owned/event TCP cancellation and legacy download/TLS', timeout_seconds=90,
                       boot_markers=('TCP_OWNED_TEST: PASS workers=8 mask=0xFF refs=8192 no_global_fd=1 reuse_after_final=1 HTTP=16384',
                                     'EVENT_TCP_TEST: PASS idle_reads=3 fresh_HTTP=16384 killed_callers=3 outputs_untouched=1 cleanup=1 shutdown=1'),
                       forbidden_markers=('TCP_OWNED_TEST: FAIL', 'EVENT_TCP_TEST: FAIL', 'THREAD_TLS_TEST: FAIL'),
                       pcap_path=ROOT / 'build/test-out/tcp-owned-network.pcap')
        if Counter(requests) != Counter(['/owned', '/event']):
            raise RuntimeError(f'expected owned/event HTTP requests, observed {requests!r}')
        if (ROOT / 'build/test-out/tcp-owned-network.pcap').stat().st_size <= 24:
            raise RuntimeError('native packet capture contains no packets')
        verify_capture(ROOT / 'build/test-out/tcp-owned-network.pcap', server.server_port)
    finally:
        server.shutdown(); server.server_close(); server_thread.join(timeout=5)
        if previous is None: os.environ.pop('IO_TCP_SELFTEST', None)
        else: os.environ['IO_TCP_SELFTEST'] = previous
        if previous_port is None: os.environ.pop('TCP_TEST_PORT', None)
        else: os.environ['TCP_TEST_PORT'] = previous_port
        subprocess.run(['make', '-W', 'src/kernel/kernel.c', 'all', 'IO_TCP_SELFTEST=0'], cwd=ROOT, check=True)
        symbols = subprocess.check_output(['x86_64-elf-nm', '--defined-only', 'build/alix.elf'], cwd=ROOT, text=True)
        if any(line.split()[-1:] in (['tcp_owned_boot_test'], ['io_event_tcp_boot_test']) for line in symbols.splitlines()):
            raise RuntimeError('ordinary kernel still includes optional TCP ownership fixture')
    print('Owned TCP lifetime native acceptance PASS; ordinary kernel restored')
    return 0

if __name__ == '__main__':
    try: sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'Owned TCP acceptance failed: {error}', file=sys.stderr)
        sys.exit(1)
