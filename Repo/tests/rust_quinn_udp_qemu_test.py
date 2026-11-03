#!/usr/bin/env python3
"""Actual Quinn UDP exchange through the native userspace socket bridge."""
import collections
import hashlib
import json
import re
import socketserver
import struct
import subprocess
import threading
from cpp_runtime_qemu_test import ROOT, run_native_elf
from udp_owned_qemu_test import Echo, requests, checksum

if __name__ == "__main__":
    with socketserver.UDPServer(("127.0.0.1", 0), Echo) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        log = ROOT / "build/test-out/quinn-udp-qemu.log"
        capture = ROOT / "build/test-out/quinn-udp-network.pcap"
        try:
            run_native_elf("rust_quinn_udp_test.elf", (
                "QUINN_UDP_TEST: PASS cpus=8 datagrams=256 std_udp=1 socket_api=1 quinn=1 ecn=1 source_override=1 endpoints=1 clone=1 nonblock=1 zero=1 mtu=1 gso_errors=1 killed_caller=1 fresh_progress=1 port_release=1",
            ), log, "Actual native Quinn UDP and public sockets", 180,
                arguments=(str(server.server_address[1]),), pcap_path=capture,
                expected_wait_status=0, fail_on_missing_markers_at_exit=True)
            endpoints = {int(port): int(cpu) for cpu, port in re.findall(r"QUINN_UDP_ENDPOINT: cpu=(\d+) port=(\d+)", log.read_text())}
            if len(endpoints) != 8:
                raise RuntimeError("missing Quinn UDP endpoints")
            data = capture.read_bytes(); endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
            cursor = 24; outgoing = collections.Counter(); incoming_ecn = {}
            while cursor < len(data):
                _, _, size, _ = struct.unpack_from(endian + "IIII", data, cursor); cursor += 16
                frame = data[cursor:cursor + size]; cursor += size
                if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[23] != 17: continue
                ip = frame[14:]; ihl = (ip[0] & 15) * 4; total = struct.unpack_from("!H", ip, 2)[0]; udp = ip[ihl:total]
                source, destination, length, check = struct.unpack_from("!HHHH", udp)
                if destination == server.server_address[1] and source in endpoints:
                    if (ip[1] & 3) != endpoints[source] & 3 or checksum(ip[:ihl]) or (check and checksum(ip[12:20] + struct.pack("!BBH", 0,17,length) + udp)):
                        raise RuntimeError("native Quinn ECN/checksum differs from wire")
                    outgoing[source] += 1
                if source == server.server_address[1] and destination in endpoints:
                    incoming_ecn.setdefault(endpoints[destination], ip[1] & 3)
            if set(outgoing.values()) != {32} or len(outgoing) != 8:
                raise RuntimeError("incomplete actual Quinn UDP workload")
            reported = {int(cpu): int(ecn) for cpu, ecn in re.findall(r"QUINN_UDP_META: cpu=(\d+) ecn=(\d+)", log.read_text())}
            if incoming_ecn != reported: raise RuntimeError("received Quinn ECN does not match packets")
            text = subprocess.check_output(["tcpdump", "-nn", "-vv", "-r", str(capture), "udp", "and", "port", str(server.server_address[1])], text=True, stderr=subprocess.STDOUT)
            capture.with_suffix(".decoded.txt").write_text(text)
            log.with_suffix(".acceptance.json").write_text(json.dumps({"scope":"Actual std/public sockets and Quinn UDP; full browser separate", "cpus":8, "quinn_datagrams":256,
                "wire_ecn_and_endpoints":True, "killed_caller_cleanup":True,
                "fresh_socket_progress":True, "port_released_after_kill":True,
                "boot":json.loads(log.with_suffix(".boot-image.json").read_text()), "capture_sha256":hashlib.sha256(data).hexdigest()}, indent=2)+"\n")
        finally:
            server.shutdown(); thread.join()
