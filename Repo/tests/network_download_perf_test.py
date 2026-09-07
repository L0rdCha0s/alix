#!/usr/bin/env python3
"""Opt-in isolated QEMU wget timings, packet evidence and persisted-file checks.

Run `make` first or omit --no-build. The production data image is cloned; all
writes, firmware state, serial logs and optional pcaps belong to this run.
The default backend is Slirp; --net-backend vmnet-shared uses the existing
socket_vmnet service and binds HTTP only to its discovered gateway address.
"""

import argparse
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import pty
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import wave
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from audio_qemu_playback_test import clone_file
import quake_gui_liveness_test as gui


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Handler(http.server.SimpleHTTPRequestHandler):
    records = []

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        started = time.monotonic()
        record = {'path': self.path, 'client_port': self.client_address[1], 'server_port': self.server.server_address[1],
                  'host_started': started, 'unix_started': time.time()}
        self.records.append(record)
        try:
            super().do_GET()
        finally:
            record['host_finished'] = time.monotonic()
            record['host_seconds'] = record['host_finished'] - started


class Guest:
    def __init__(self, temporary, snapshot, out, pcap, phase, net_backend='user'):
        self.temp, self.out = temporary, out
        self.log = out / f'{phase}-serial.log'
        self.log.write_text('')
        self.qmp_path = temporary / f'{phase}-qmp.sock'
        self.pid_path = temporary / f'{phase}-qemu.pid'
        probe = socket.socket()
        probe.bind(('127.0.0.1', 0))
        self.gdb_port = probe.getsockname()[1]
        probe.close()
        (out / f'{phase}-guest.json').write_text(json.dumps({'qmp': str(self.qmp_path), 'gdb_port': self.gdb_port, 'pidfile': str(self.pid_path)}))
        self.master, slave = pty.openpty()
        real_qemu = shutil.which('qemu-system-x86_64')
        boot = temporary / 'boot'
        if not boot.exists():
            (boot / 'EFI' / 'BOOT').mkdir(parents=True)
            shutil.copy2(snapshot / 'alix.elf', boot / 'alix.elf')
            shutil.copy2(snapshot / 'EFI' / 'BOOT' / 'BOOTX64.EFI', boot / 'EFI' / 'BOOT' / 'BOOTX64.EFI')
        wrapper = temporary / 'qemu-wrapper'
        wrapper.write_text('#!/usr/bin/env python3\nimport os, sys\n'
                           'args = sys.argv[1:]\n'
                           f"args = [a.replace('file=fat:rw:build,', 'file=fat:rw:{boot},') for a in args]\n"
                           f'os.execv({real_qemu!r}, [{real_qemu!r}] + args)\n')
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env['MAKEFLAGS'] = (f"QEMU={wrapper} OVMF_VARS={temporary / 'vars.fd'} "
                            'SMP_CORES=8 QEMU_ACCEL=tcg')
        env.update({'QEMU_GDB_FLAGS': f'-display none -qmp unix:{self.qmp_path},server,nowait -gdb tcp:127.0.0.1:{self.gdb_port} -pidfile {self.pid_path}', 'QEMU_DEBUG_FLAGS': '',
                    'QEMU_DATA_IMG': str(temporary / 'data.img'),
                    'QEMU_SERIAL_LOG': str(self.log), 'QEMU_TIMEOUT_SECONDS': '1800',
                    'AUDIO_DEV': 'none', 'NET_BACKEND': net_backend,
                    'NETDUMP': f'-object filter-dump,id=n0dump,netdev=n0,queue=all,file={out / "qemu-net.pcap"}' if pcap else ''})
        self.runner = subprocess.Popen([str(ROOT / 'run-via-agent.sh')], cwd=ROOT, env=env,
                                       stdin=slave, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       start_new_session=True)
        os.close(slave)
        try:
            self.wait('login:', timeout=120)
            self.send('root')
            self.wait('password:', timeout=15)
            self.send('root')
            self.wait('root@alix$', timeout=30)
            # Startup may run external NTP retries concurrently with the login
            # shell. Let it finish so those requests do not perturb timed traffic.
            deadline = time.monotonic() + 120
            while not re.search(r'\[proc\] destroy[^\r\n]*name=startup\b', self.text()):
                gui.ensure_guest_healthy(self.runner, self.text())
                if time.monotonic() >= deadline:
                    raise RuntimeError('startup did not finish before network timing')
                time.sleep(.05)
        except BaseException:
            self.close()
            raise

    def text(self):
        return self.log.read_bytes().decode('utf-8', errors='replace')

    def send(self, command):
        os.write(self.master, (command + '\r').encode('ascii'))

    def wait(self, token, offset=0, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            text = self.text()
            if token in text[offset:]:
                return text[offset:]
            gui.ensure_guest_healthy(self.runner, text)
            time.sleep(.02)
        raise RuntimeError(f'timeout waiting for {token!r}; inspect {self.log}')

    def command(self, command, token='root@alix$', timeout=300, powercut=False):
        offset = len(self.text())
        start = time.monotonic()
        marker = f'__NETPERF_{time.monotonic_ns()}__'
        # Input redraws and interleaved IRQ logs can resemble shell prompts.
        # A separate echo produces a unique complete output line after exit.
        self.send(command if powercut else command + '\recho ' + marker)
        deadline = start + timeout
        saved_at = None
        pattern = re.compile(r'(?:^|[\r\n])' + re.escape(marker) + r'(?:[\r\n]|$)')
        while time.monotonic() < deadline:
            text = self.text()[offset:]
            if saved_at is None and token != 'root@alix$' and token in text:
                saved_at = time.monotonic()
                if powercut:
                    self.close()
                    return saved_at - start, text
            if pattern.search(text):
                return (saved_at or time.monotonic()) - start, text
            gui.ensure_guest_healthy(self.runner, self.text())
            time.sleep(.02)
        raise RuntimeError(f'timeout running {command!r}; inspect {self.log}')

    def shutdown(self):
        offset = len(self.text())
        self.send('shutdown')
        # QEMU can power off before its final serial FIFO is flushed. The
        # subsequent cold boot/hash is the persistence check, not this text.
        self.runner.wait(timeout=180)
        text = self.text()[offset:]
        if self.runner.returncode != 0 or 'Syncing disks...' not in text or 'failed to sync' in text:
            raise RuntimeError('guest shutdown failed to persist filesystem')
        os.close(self.master)
        self.master = -1

    def close(self):
        # run-via-agent.sh places its make/QEMU child in another session, so
        # stopping only the outer runner can leave an orphan consuming CPU.
        if self.pid_path.exists():
            try:
                qmp = gui.QmpClient(self.qmp_path, timeout=1)
                try:
                    qmp.quit()
                finally:
                    qmp.close()
            except Exception:
                try:
                    os.kill(int(self.pid_path.read_text()), signal.SIGTERM)
                except (OSError, ValueError):
                    pass
            try:
                self.runner.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        gui.stop_subprocess(self.runner)
        if self.master >= 0:
            os.close(self.master)
            self.master = -1


def analyse_pcap(path, port):
    destination = path.with_suffix('.tcpdump.txt')
    with destination.open('w') as output:
        subprocess.run(['tcpdump', '-nn', '-tt', '-S', '-r', str(path), f'tcp port {port}'],
                       stdout=output, stderr=subprocess.PIPE, check=True)
    flows = {}
    packet = re.compile(r'^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): (.*)')
    for line in destination.read_text().splitlines():
        match = packet.match(line)
        if not match:
            continue
        ts, src, sport, dst, dport, detail = match.groups()
        ts, sport, dport = float(ts), int(sport), int(dport)
        server = sport == port
        key = dport if server else sport
        item = flows.setdefault(key, {'client_port': key, 'server_payload_packets': 0,
                                     'server_payload_bytes': 0, 'repeated_payload_segments': 0, 'overlapping_payload_bytes': 0, 'guest_ack_packets': 0,
                                     'zero_window_packets': 0, 'max_server_gap_seconds': 0,
                                     'max_guest_gap_seconds': 0, 'server_gaps_over_50ms': 0,
                                     '_seen': set()})
        if not server:
            item['guest_ack_packets'] += 'ack ' in detail
            if '_last_guest' in item:
                item['max_guest_gap_seconds'] = max(item['max_guest_gap_seconds'], ts - item['_last_guest'])
            item['_last_guest'] = ts
            if re.search(r'win 0(?:,|\s|$)', detail):
                item['zero_window_packets'] += 1
        sequence = re.search(r'seq (\d+):(\d+)', detail)
        if server and sequence:
            first, last = map(int, sequence.groups())
            if last > first:
                if '_last_server' in item:
                    gap = ts - item['_last_server']
                    item['max_server_gap_seconds'] = max(item['max_server_gap_seconds'], gap)
                    item['server_gaps_over_50ms'] += gap > .05
                else:
                    item['first_payload_timestamp'] = ts
                item['_last_server'] = ts
                item['server_payload_packets'] += 1
                item['server_payload_bytes'] += last - first
                item['repeated_payload_segments'] += (first, last) in item['_seen']
                item['_seen'].add((first, last))
                high = item.get('_highest_seq', first)
                item['overlapping_payload_bytes'] += max(0, min(last, high) - first)
                item['_highest_seq'] = max(high, last)
    for item in flows.values():
        if '_last_server' in item:
            item['payload_span_seconds'] = item['_last_server'] - item['first_payload_timestamp']
        for key in list(item):
            if key.startswith('_'):
                del item[key]
    return list(flows.values())



def verify_installation(guest, snapshot, out, port, result):
    """Run the shipped bootstrap and verify installed archive members in guest."""
    guest.command('mkdir /tmp')
    bootstrap = snapshot / 'http' / 'unzip.elf'
    digest = hashlib.sha1(bootstrap.read_bytes()).hexdigest()
    elapsed, text = guest.command(f'wget http://gateway:{port}/unzip.elf /tmp/dl-unzip.elf',
                                   f'Saved {bootstrap.stat().st_size} bytes to /tmp/dl-unzip.elf')
    _, checksum = guest.command('sha1sum /tmp/dl-unzip.elf', digest)
    result['bootstrap'] = {'bytes': bootstrap.stat().st_size, 'sha1': digest,
                           'wall_seconds': elapsed, 'verified': digest in checksum}
    (out / 'bootstrap-download.log').write_text(text + checksum)
    if not result['bootstrap']['verified']:
        raise RuntimeError('stripped bootstrap download/hash failed; inspect bootstrap-download.log')
    elapsed, text = guest.command('runelf /tmp/dl-unzip.elf /root/network-perf-zip.bin /root/usr/bin', timeout=300)
    (out / 'archive-install.log').write_text(text)
    result['archive_extract_seconds'] = elapsed
    result['runtime_files'] = []
    with zipfile.ZipFile(snapshot / 'http' / 'user-elfs.zip') as archive:
        for name in archive.namelist():
            if Path(name).name != name or not name.endswith('.elf'):
                raise RuntimeError(f'unexpected runtime archive entry: {name}')
            digest = hashlib.sha1(archive.read(name)).hexdigest()
            _, checksum = guest.command(f'sha1sum /root/usr/bin/{name}', digest, 180)
            result['runtime_files'].append({'name': name, 'sha1': digest, 'verified': digest in checksum})
            (out / ('installed-' + name + '.log')).write_text(checksum)
    if not all(item['verified'] for item in result['runtime_files']):
        raise RuntimeError('runtime archive extraction/hash verification failed; inspect archive-install.log')
    guest.command(f'wget http://gateway:{port}/runtime-smoke.wav /tmp/runtime-smoke.wav')
    _, text = guest.command('runelf /root/usr/bin/playsound.elf /tmp/runtime-smoke.wav', timeout=30)
    (out / 'runtime-smoke.log').write_text(text)
    result['runtime_smoke'] = ('start name=/root/usr/bin/playsound.elf' in text and
                               'playsound:' not in text and 'failed to start process' not in text)
    print(f"Installed {len(result['runtime_files'])} runtime ELFs; all hashes="
          f"{all(item['verified'] for item in result['runtime_files'])}, stripped app smoke={result['runtime_smoke']}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', default='download')
    parser.add_argument('--net-backend', choices=['user', 'vmnet-shared'], default='user')
    parser.add_argument('--http-bind', help='host address to bind (auto-detect socket_vmnet gateway by default)')
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--pcap', action='store_true')
    parser.add_argument('--probe', type=Path)
    parser.add_argument('--install-archive', action='store_true',
                        help='after reboot, run stripped bootstrap and verify every installed runtime ELF')
    parser.add_argument('--wget-profile', action='store_true')
    parser.add_argument('--igb-stats', action='store_true')
    parser.add_argument('--no-reboot', action='store_true')
    parser.add_argument('--powercut-after-save', action='store_true',
                        help='quit QEMU immediately after final disk Saved, then cold-boot and verify')
    parser.add_argument('--repeat', type=int, default=2)
    parser.add_argument('--files', nargs='+', choices=['zip', '1m', '8m'], default=['1m', '8m', 'zip'])
    args = parser.parse_args()
    if args.install_archive and (args.no_reboot or 'zip' not in args.files):
        parser.error('--install-archive requires zip and reboot verification')
    if args.powercut_after_save and args.no_reboot:
        parser.error('--powercut-after-save requires reboot verification')
    if args.repeat < 1:
        parser.error('--repeat must be positive')
    if not args.no_build:
        subprocess.run(['make'], cwd=ROOT, check=True)
    out = ROOT / 'test-out' / ('network-' + args.label)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='alix-netperf-') as temporary:
        temporary = Path(temporary)
        snapshot = args.snapshot.resolve() if args.snapshot else temporary / 'snapshot'
        if not args.snapshot:
            (snapshot / 'EFI' / 'BOOT').mkdir(parents=True)
            (snapshot / 'http').mkdir()
            shutil.copy2(ROOT / 'build' / 'alix.elf', snapshot / 'alix.elf')
            shutil.copy2(ROOT / 'build' / 'EFI' / 'BOOT' / 'BOOTX64.EFI', snapshot / 'EFI' / 'BOOT' / 'BOOTX64.EFI')
            shutil.copy2(ROOT / 'build' / 'user' / 'user-elfs.zip', snapshot / 'http' / 'user-elfs.zip')
        if args.install_archive:
            if not (snapshot / 'http' / 'unzip.elf').exists():
                shutil.copy2(ROOT / 'build' / 'user' / 'runtime' / 'unzip.elf', snapshot / 'http' / 'unzip.elf')
            with wave.open(str(snapshot / 'http' / 'runtime-smoke.wav'), 'wb') as sound:
                sound.setnchannels(2)
                sound.setsampwidth(2)
                sound.setframerate(48000)
                sound.writeframes(bytes(1920 * 4))
        if args.probe:
            shutil.copy2(args.probe, snapshot / 'http' / 'copy-probe.elf')
        clone_file(ROOT / 'data.img', temporary / 'data.img')
        shutil.copy2(ROOT / 'vendor' / 'OVMF_VARS-1024x768.fd', temporary / 'vars.fd')
        fixtures = {'zip': 'user-elfs.zip', '1m': 'deterministic-1m.bin', '8m': 'deterministic-8m.bin'}
        seed = bytes(range(256)) * 4096
        for name, count in [('deterministic-1m.bin', 1), ('deterministic-8m.bin', 8)]:
            (snapshot / 'http' / name).write_bytes(seed * count)
        expected = {key: {'size': (snapshot / 'http' / name).stat().st_size,
                           'sha1': hashlib.sha1((snapshot / 'http' / name).read_bytes()).hexdigest()}
                    for key, name in fixtures.items()}
        Handler.records = []
        handler = functools.partial(Handler, directory=str(snapshot / 'http'))
        bind_address = args.http_bind
        if not bind_address and args.net_backend == 'user':
            bind_address = '127.0.0.1'
        if not bind_address:
            processes = subprocess.check_output(['ps', '-axo', 'command'], text=True)
            for line in processes.splitlines():
                if not re.match(r'^\S*/socket_vmnet\s', line):
                    continue
                gateway = re.search(r'--vmnet-gateway[= ](\d+\.\d+\.\d+\.\d+)', line)
                if gateway:
                    bind_address = gateway.group(1)
                    break
        if not bind_address:
            raise RuntimeError('cannot find socket_vmnet gateway; pass --http-bind with its host address')
        server = Server((bind_address, 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]
        result = {'kernel_sha256': hashlib.sha256((snapshot / 'alix.elf').read_bytes()).hexdigest(),
                  'pcap_enabled': args.pcap, 'cores': 8, 'accelerator': 'tcg', 'nic': 'igb',
                  'network_backend': args.net_backend, 'http_bind': bind_address, 'startup_waited': True, 'qemu_version': subprocess.check_output(['qemu-system-x86_64', '--version'], text=True).splitlines()[0],
                  'fixtures': expected, 'transfers': [], 'persistence': [], 'http_port': port}
        def save():
            result['http_requests'] = [dict(record) for record in Handler.records]
            (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        guest = None
        try:
            print(f'Starting isolated guest: {out}', flush=True)
            guest = Guest(temporary, snapshot, out, args.pcap, 'download', args.net_backend)
            guest.command('mkdir /tmp')
            if args.probe:
                guest.command(f'wget http://gateway:{port}/copy-probe.elf /tmp/copy-probe.elf')
                elapsed, probe = guest.command('runelf /tmp/copy-probe.elf', timeout=180)
                (out / 'copy-probe.log').write_text(probe)
                result['copy_probe_seconds'] = elapsed
                print('\n'.join(line for line in probe.splitlines() if '[copy-probe]' in line), flush=True)
            if args.igb_stats:
                _, stats = guest.command('cat /proc/sys/net/igb_stats')
                (out / 'igb-stats-before.log').write_text(stats)
            _, mount = guest.command('mount')
            (out / 'mounts.txt').write_text(mount)
            for key in args.files:
                filename = fixtures[key]
                for destination in ['/tmp', '/root']:
                    path = f'{destination}/network-perf-{key}.bin'
                    for repeat in range(args.repeat):
                        print(f'Downloading {key} to {destination}, iteration {repeat + 1}', flush=True)
                        command = f'wget {"--profile " if args.wget_profile else ""}http://gateway:{port}/{filename} {path}'
                        powercut = args.powercut_after_save and key == args.files[-1] and destination == '/root' and repeat == args.repeat - 1
                        elapsed, text = guest.command(command, f"Saved {expected[key]['size']} bytes to {path}", 600, powercut=powercut)
                        (out / f'{key}-{destination[1:]}-{repeat}.log').write_text(text)
                        if powercut:
                            checksum = 'Hash deferred to cold reboot; no guest shutdown or sync after Saved.\n'
                            result['powercut_after_saved'] = True
                        else:
                            _, checksum = guest.command(f'sha1sum {path}', expected[key]['sha1'], 180)
                        saved_ok = f"Saved {expected[key]['size']} bytes to {path}" in text
                        hash_ok = None if powercut else expected[key]['sha1'] in checksum
                        (out / f'{key}-{destination[1:]}-{repeat}-sha1.log').write_text(checksum)
                        record = {'fixture': key, 'destination': destination, 'repeat': repeat,
                                  'wall_seconds': elapsed, 'mib_per_second': expected[key]['size'] / 1048576 / elapsed,
                                  'size': expected[key]['size'], 'sha1': expected[key]['sha1'], 'saved_complete': saved_ok, 'hash_matches': hash_ok, 'powercut_after_saved': powercut, 'verified': saved_ok and (powercut or hash_ok)}
                        result['transfers'].append(record)
                        save()
                        print(json.dumps(record), flush=True)
            if args.igb_stats and not result.get('powercut_after_saved'):
                _, stats = guest.command('cat /proc/sys/net/igb_stats')
                (out / 'igb-stats-after.log').write_text(stats)
            if not result.get('powercut_after_saved'):
                guest.shutdown()
            guest.close()
            guest = None
            if args.pcap:
                result['packet_flows'] = analyse_pcap(out / 'qemu-net.pcap', port)
                save()
            if not args.no_reboot:
                print('Rebooting cloned disk to verify persisted hashes', flush=True)
                if args.install_archive:
                    # A cold guest restarts its ephemeral TCP ports. A new host
                    # listener avoids stale pre-reboot TIME_WAIT tuples on vmnet.
                    server.shutdown()
                    server.server_close()
                    server = Server((bind_address, 0), handler)
                    threading.Thread(target=server.serve_forever, daemon=True).start()
                    port = server.server_address[1]
                    result['post_reboot_http_port'] = port
                guest = Guest(temporary, snapshot, out, False, 'reboot', args.net_backend)
                for key in args.files:
                    path = f'/root/network-perf-{key}.bin'
                    elapsed, text = guest.command(f'sha1sum {path}', expected[key]['sha1'], 180)
                    result['persistence'].append({'path': path, 'sha1': expected[key]['sha1'], 'verified_after_reboot': expected[key]['sha1'] in text})
                if args.install_archive:
                    verify_installation(guest, snapshot, out, port, result)
                guest.shutdown()
                guest.close()
                guest = None
            result['success'] = all(item['verified'] for item in result['transfers']) and all(item['verified_after_reboot'] for item in result['persistence'])
            if args.install_archive:
                result['success'] = result['success'] and result['bootstrap']['verified'] and result['runtime_smoke'] and all(item['verified'] for item in result['runtime_files'])
            save()
            print(json.dumps(result, indent=2), flush=True)
        finally:
            if guest:
                guest.close()
            server.shutdown()
            server.server_close()
            save()
    return 0 if result.get('success') else 1


if __name__ == '__main__':
    raise SystemExit(main())
