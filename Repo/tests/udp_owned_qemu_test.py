#!/usr/bin/env python3
"""Native UDP core packets, eight CPUs, DNS/NTP leases and ordinary-kernel restore."""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import socketserver
import struct
import subprocess
import threading
from cpp_runtime_qemu_test import ROOT, run_native_elf

requests = []
dns_requests = []

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        requests.append((self.client_address, data))
        sock.sendto(data, self.client_address)

class Dns(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        p = 12
        while query[p]:
            p += 1 + query[p]
        end = p + 5
        dns_requests.append(query)
        answer = (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:end] +
                  b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("10.0.2.2"))
        sock.sendto(answer, self.client_address)

def checksum(data):
    if len(data) & 1:
        data += b"\0"
    value = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535

def verify_capture(path, echo_port, dns_port, log):
    endpoints = re.findall(r"UDP_CORE_ENDPOINT: cpu=(\d+) port=(\d+) tos=(\d+) ttl=(\d+)", log)
    if len(endpoints) != 8 or {int(e[0]) for e in endpoints} != set(range(8)):
        raise RuntimeError("incomplete native UDP endpoint records")
    ports = {int(port): (int(cpu), int(tos), int(ttl)) for cpu, port, tos, ttl in endpoints}
    outgoing, incoming = collections.defaultdict(list), collections.defaultdict(list)
    received_tos = {}
    dns_ports = set()
    raw = path.read_bytes()
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(raw[:4])
    if not endian or struct.unpack_from(endian + "I", raw, 20)[0] != 1:
        raise RuntimeError("unexpected native Ethernet capture format")
    cursor = 24
    while cursor < len(raw):
        _, _, size, _ = struct.unpack_from(endian + "IIII", raw, cursor)
        cursor += 16
        frame = raw[cursor:cursor + size]
        cursor += size
        if len(frame) != size:
            raise RuntimeError("truncated native capture")
        if len(frame) < 42 or frame[12:14] != b"\x08\x00":
            continue
        ip = frame[14:]
        ihl, total = (ip[0] & 15) * 4, struct.unpack_from("!H", ip, 2)[0]
        if ip[9] != 17:
            continue
        udp = ip[ihl:total]
        source, destination, length, check = struct.unpack_from("!HHHH", udp)
        if source not in (echo_port, dns_port) and destination not in (echo_port, dns_port):
            continue
        if checksum(ip[:ihl]) or length != len(udp):
            raise RuntimeError("invalid UDP/IP wire length or header checksum")
        if check and checksum(ip[12:20] + struct.pack("!BBH", 0, 17, length) + udp):
            raise RuntimeError("invalid UDP wire checksum")
        if destination == dns_port:
            dns_ports.add(source)
        if destination == echo_port:
            if source not in ports:
                raise RuntimeError("UDP packet has an unreported native source port")
            _, tos, ttl = ports[source]
            if ip[1] != tos or ip[8] != ttl or not struct.unpack_from("!H", ip, 6)[0] & 0x4000:
                raise RuntimeError("native UDP TOS/TTL/DF metadata differs from packets")
            outgoing[source].append(length - 8)
        if source == echo_port:
            incoming[destination].append(length - 8)
            received_tos.setdefault(ports[destination][0], ip[1])
    expected = collections.Counter([0, 1, 17, 1472, 511][n % 5] for n in range(32))
    for port in ports:
        if collections.Counter(outgoing[port]) != expected or collections.Counter(incoming[port]) != expected:
            raise RuntimeError("native UDP datagram sizes/counts differ from capture")
    if not dns_ports or dns_ports & set(ports):
        raise RuntimeError("built-in DNS reused a live application UDP port")
    reported_tos = {int(cpu): int(tos) for cpu, tos in re.findall(r"UDP_CORE_RECEIVE_META: cpu=(\d+) tos=(\d+)", log)}
    if reported_tos != received_tos:
        raise RuntimeError("native received TOS differs from the actual packet headers")
    decoded = subprocess.check_output(["tcpdump", "-nn", "-vv", "-r", str(path),
        "udp", "and", "port", str(echo_port)], text=True, stderr=subprocess.STDOUT)
    path.with_suffix(".decoded.txt").write_text(decoded)
    return {"cpus": 8, "outgoing_datagrams": 256, "incoming_datagrams": 256,
            "packet_checksums": True, "ecn_ttl_df": True, "dns_port_collisions": False}

def main():
    echo = socketserver.UDPServer(("127.0.0.1", 0), Echo)
    dns = socketserver.UDPServer(("127.0.0.1", 0), Dns)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (echo, dns)]
    for thread in threads:
        thread.start()
    old = {key: os.environ.get(key) for key in ("UDP_SELFTEST", "UDP_TEST_PORT", "UDP_DNS_PORT")}
    out = ROOT / "build/ports/zen/udp-core"
    out.mkdir(parents=True, exist_ok=True)
    log = ROOT / "build/test-out/udp-owned-qemu.log"
    capture = ROOT / "build/test-out/udp-owned-network.pcap"
    try:
        os.environ.update(UDP_SELFTEST="1", UDP_TEST_PORT=str(echo.server_address[1]), UDP_DNS_PORT=str(dns.server_address[1]))
        subprocess.run(["make", "-W", "src/kernel/kernel.c", "-W", "tests/udp_owned_boot_test.c",
                        "all", "UDP_SELFTEST=1", "build/user/thread_tls_test.elf"], cwd=ROOT, check=True)
        shutil.copyfile(ROOT / "build/alix.elf", out / "validated-alix.elf")
        run_native_elf("thread_tls_test.elf", ("THREAD_TLS_TEST: PASS",), log,
            "Native UDP transport and legacy TCP/TLS regression", timeout_seconds=110,
            boot_markers=("UDP_CORE_TEST: PASS cpus=8 mask=0xFF datagrams=256 zero=1 max_mtu=1 peek=1 truncation=1 ownership=1 ecn=1 dns=1 ntp=1 cleanup=1",),
            forbidden_markers=("UDP_CORE_TEST: FAIL", "THREAD_TLS_TEST: FAIL"), pcap_path=capture)
        if len(requests) != 256 or not dns_requests:
            raise RuntimeError("host did not observe the complete UDP/DNS workload")
        receipt = verify_capture(capture, echo.server_address[1], dns.server_address[1], log.read_text())
        receipt.update(scope="Native owned UDP transport core; userspace sockets/Quinn remain separate",
                       boot=json.loads(log.with_suffix(".boot-image.json").read_text()),
                       capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest(),
                       validated_kernel_sha256=hashlib.sha256((out / "validated-alix.elf").read_bytes()).hexdigest())
        (out / "native-acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n")
    finally:
        for server in (echo, dns):
            server.shutdown(); server.server_close()
        for thread in threads:
            thread.join()
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        subprocess.run(["make", "-W", "src/kernel/kernel.c", "all", "UDP_SELFTEST=0"], cwd=ROOT, check=True)
        symbols = subprocess.check_output(["x86_64-elf-nm", "--defined-only", "build/alix.elf"], cwd=ROOT, text=True)
        if any(line.split()[-1:] == ["udp_owned_boot_test"] for line in symbols.splitlines()):
            raise RuntimeError("ordinary kernel still contains the UDP boot fixture")
    print("Native UDP core acceptance PASS; ordinary kernel restored")

if __name__ == "__main__":
    main()
