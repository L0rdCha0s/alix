#!/usr/bin/env python3
"""Native DNS/libc lookup through an independent controlled UDP DNS server."""
from cpp_runtime_qemu_test import ROOT, run_native_elf
import socketserver
import threading
import struct
import socket
import subprocess
import hashlib
import json
import re


def name_wire(name):
    return b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.')) + b'\0'


def record(owner, kind, data):
    return name_wire(owner) + struct.pack('!HHIH', kind, 1, 60, len(data)) + data


class Dns(socketserver.BaseRequestHandler):
    def handle(self):
        request, endpoint = self.request
        if len(request) < 17:
            raise RuntimeError('short guest DNS request')
        cursor, labels = 12, []
        while request[cursor]:
            length = request[cursor]
            labels.append(request[cursor + 1:cursor + 1 + length].decode('ascii'))
            cursor += length + 1
        cursor += 5
        question = request[12:cursor]
        name = '.'.join(labels)
        with self.server.state_lock:
            self.server.seen.add(name)
            observed = 'blocked.test' in self.server.seen
        if name == 'blocked.test':
            return
        flags, answers = 0x8180, []
        if name == 'missing.test':
            flags = 0x8183
        elif name == 'temporary.test':
            flags = 0x8182
        elif name == 'truncated.test':
            flags = 0x8380
        elif name == 'invalid.test':
            position = 12 + len(question)
            answers = [struct.pack('!H', 0xc000 | position) + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x0a\x01\x02\x03']
        elif name in ('alias.test', 'hop.test'):
            answers = [record(name, 5, name_wire('canonical.test'))]
            if name == 'alias.test':
                answers += [record('canonical.test', 1, socket.inet_aton(ip)) for ip in ('10.1.2.3', '10.1.2.4')]
        elif name == 'canonical.test':
            answers = [record(name, 1, socket.inet_aton(ip)) for ip in ('10.1.2.3', '10.1.2.4')]
        else:
            ip = '10.20.30.2' if name == 'observed.test' and observed else '10.20.30.1' if name == 'observed.test' else '10.0.2.2'
            answers = [record(name, 1, socket.inet_aton(ip))]
        if name == 'wrong-question.test':
            wrong = request[:2] + struct.pack('!HHHHH', 0x8183, 1, 0, 0, 0) + name_wire('different.test') + struct.pack('!HH', 1, 1)
            endpoint.sendto(wrong, self.client_address)
        response = request[:2] + struct.pack('!HHHHH', flags, 1, len(answers), 0, 0) + question + b''.join(answers)
        endpoint.sendto(response, self.client_address)


class Data(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        request = b''
        while len(request) < 3:
            data = self.request.recv(3 - len(request))
            if not data:
                raise RuntimeError('guest closed resolved TCP connection before sending its request')
            request += data
        if request != b'DNS':
            raise RuntimeError('unexpected resolved TCP request')
        self.request.sendall(b'resolved')


if __name__ == '__main__':
    with socketserver.ThreadingUDPServer(('127.0.0.1', 0), Dns) as dns, socketserver.ThreadingTCPServer(('127.0.0.1', 0), Data) as data:
        dns.daemon_threads = data.daemon_threads = True
        dns.state_lock, dns.seen = threading.Lock(), set()
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (dns, data)]
        for thread in threads:
            thread.start()
        log = ROOT / 'build/test-out/netdb-native-qemu.log'
        capture = ROOT / 'build/test-out/netdb-native-network.pcap'
        try:
            run_native_elf('netdb_test.elf',
                ('NETDB_TEST: PASS cpus=8 multi_a=1 cname=1 negatives=1 tls=1 tcp=1 copy_checks=1 canceled_caller=1',),
                log, 'native DNS and libc netdb', 140,
                arguments=(str(dns.server_address[1]), str(data.server_address[1])),
                expected_wait_status=0, fail_on_missing_markers_at_exit=True, pcap_path=capture)
            with dns.state_lock:
                seen = sorted(dns.seen)
            required = {'alias.test', 'hop.test', 'canonical.test', 'missing.test', 'temporary.test', 'invalid.test',
                        'truncated.test', 'wrong-question.test', 'blocked.test', 'observed.test', 'fresh.test', 'connect.test'}
            if not required <= set(seen):
                raise RuntimeError('native resolver did not exercise the expected DNS wire cases')
            packets = subprocess.check_output(['tcpdump', '-nn', '-vv', '-T', 'domain', '-r', str(capture), f'udp port {dns.server_address[1]}'],
                                              text=True, stderr=subprocess.STDOUT)
            log.with_suffix('.dns.pcap.txt').write_text(packets)
            if 'CNAME' not in packets or 'NXDomain' not in packets:
                raise RuntimeError('captured DNS responses lack CNAME or negative reply evidence')
            receipt = {'scope': 'Native IPv4 DNS/netdb with an explicit per-call controlled resolver; full NSPR/NSS, default external DNS and Zen remain unverified',
                'cpus': 8, 'dns_names': seen, 'canceled_caller': True, 'resolved_tcp_connections': 8,
                'boot_images': json.loads(log.with_suffix('.boot-image.json').read_text()),
                'capture_sha256': hashlib.sha256(capture.read_bytes()).hexdigest()}
            log.with_suffix('.acceptance.json').write_text(json.dumps(receipt, indent=2) + '\n')
        finally:
            dns.shutdown()
            data.shutdown()
            for thread in threads:
                thread.join(timeout=3)
