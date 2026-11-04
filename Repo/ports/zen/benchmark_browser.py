#!/usr/bin/env python3
"""Measure native Zen in a disposable QEMU disk, through disposable privileged instrumentation.

The supplied disk must already contain Zen. It is cloned, never booted in place.
Browser times use Performance APIs; host wall times and QMP screenshots are
recorded separately. The instrumentation exists only in the private test VM.
"""
import argparse
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests'))
from quake_gui_liveness_test import move_mouse_to_terminal


class QMP:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.connect(str(path))
        self.file = self.socket.makefile('rwb', buffering=0)
        self.file.readline()
        self.call('qmp_capabilities')

    def call(self, command, arguments=None):
        self.file.write(json.dumps({'execute': command, 'arguments': arguments or {}}).encode() + b'\n')
        while True:
            value = json.loads(self.file.readline())
            if 'error' in value:
                raise RuntimeError(value)
            if 'return' in value:
                return value['return']

    execute = call

    def human(self, command):
        return self.call('human-monitor-command', {'command-line': command})

    def key(self, key, down):
        self.call('input-send-event', {'events': [
            {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': key}}}
        ]})

    def type(self, text):
        names = {' ': 'spc', '/': 'slash', '.': 'dot', '_': 'minus', '-': 'minus'}
        for char in text:
            if char == '_':
                self.key('shift', True)
            key = names.get(char, char)
            self.key(key, True)
            time.sleep(.05)
            self.key(key, False)
            if char == '_':
                self.key('shift', False)
            time.sleep(.05)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--url', action='append', default=[])
    parser.add_argument('--ram', default='4G')
    parser.add_argument('--kernel', type=Path, default=ROOT / 'build/alix.elf')
    parser.add_argument('--bundle', type=Path, help='install this Zen ZIP in the disposable disk before measuring')
    parser.add_argument('--quantum', type=int, help='experimental normal-thread quantum, in 10 ms ticks')
    parser.add_argument('--steal', action='store_true', help='enable the optional kernel work stealing')
    parser.add_argument('--timeout', type=int, default=240)
    parser.add_argument('--repeat', type=int, default=1, help='repeat the URL sequence in the same browser')
    args = parser.parse_args()
    args.url = args.url or ['https://www.smh.com.au/']
    if not 1 <= args.repeat <= 20:
        parser.error('--repeat must be 1..20')
    args.url *= args.repeat
    source = args.data_image.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'disk_source': str(source), 'source_modified': False, 'ram': args.ram,
              'cpus': 8, 'cpu': 'max,+rdrand', 'pages': [], 'paint_events': [],
              'quantum_override': args.quantum, 'steal_override': args.steal}
    profile_path = '/root/zenbench-' + secrets.token_hex(4)
    report['profile'] = profile_path
    report['kernel_sha256'] = hashlib.sha256(args.kernel.read_bytes()).hexdigest()
    start = time.monotonic()
    def event(name, **values):
        item = dict(event=name, host_seconds=time.monotonic() - start, **values)
        with (output / 'events.jsonl').open('a') as log:
            log.write(json.dumps(item) + '\n')
        print(json.dumps(item), flush=True)
        return item['host_seconds']
    # Keep AF_UNIX paths within Darwin's 104-byte limit.
    with tempfile.TemporaryDirectory(prefix='azb-') as temporary:
        work = Path(temporary)
        disk = work / 'data.img'
        subprocess.run(['cp', '-c' if os.uname().sysname == 'Darwin' else '--reflink=auto', str(source), str(disk)], check=True)
        assert disk.stat().st_ino != source.stat().st_ino
        boot = work / 'boot'
        (boot / 'EFI/BOOT').mkdir(parents=True)
        shutil.copyfile(args.kernel, boot / 'alix.elf')
        if hashlib.sha256((boot / 'alix.elf').read_bytes()).hexdigest() != report['kernel_sha256']:
            raise RuntimeError('kernel changed while the benchmark snapshot was captured')
        shutil.copyfile(ROOT / 'build/EFI/BOOT/BOOTX64.EFI', boot / 'EFI/BOOT/BOOTX64.EFI')
        shutil.copyfile(ROOT / 'vendor/OVMF_VARS-1024x768.fd', work / 'vars.fd')
        served = work / 'served'
        served.mkdir()
        shutil.copyfile(ROOT / 'build/user/atk_shell.elf', served / 'atk_shell.elf')
        shutil.copyfile(ROOT / 'test1.htm', served / 'test1.htm')
        if args.bundle:
            bundle = args.bundle.resolve(strict=True)
            with bundle.open('rb') as stream:
                report['bundle_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            shutil.copyfile(bundle, served / 'zen.zip')
            shutil.copyfile(ROOT / 'build/user/runtime/unzip.elf', served / 'unzip.elf')
        (served / 'user.js').write_text('\n'.join(
            'user_pref(' + json.dumps(key) + ', ' + json.dumps(value) + ');'
            for key, value in {
                'browser.shell.checkDefaultBrowser': False,
                'browser.startup.page': 0,
                'browser.aboutwelcome.enabled': False,
                'zen.welcome-screen.seen': True,
                'browser.startup.homepage_override.mstone': 'ignore',
                'browser.startup.homepage': 'about:blank',
            }.items()) + '\n')
        observations = []
        class Handler(SimpleHTTPRequestHandler):
            def do_GET(self):
                uri = urlsplit(self.path)
                if uri.path == '/__report':
                    value = json.loads(parse_qs(uri.query)['data'][0])
                    observations.append((time.monotonic() - start, value))
                    self.send_response(200)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                else:
                    super().do_GET()
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(served)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        args.url = [f'http://10.0.2.2:{server.server_port}/test1.htm' if url == 'local' else url for url in args.url]
        (served / 'benchmark.js').write_text('pref("general.config.filename", "alix-benchmark.cfg");\npref("general.config.obscure_value", 0);\npref("general.config.sandbox_enabled", false);\n')
        config = '// Native Alix disposable benchmark\nconst ALIX_BENCH_URLS = ' + json.dumps(args.url) + ';\nconst ALIX_BENCH_TIMEOUT = ' + str(args.timeout * 1000) + ';\n'
        config += 'const ALIX_BENCH_COLLECTOR = "http://10.0.2.2:' + str(server.server_port) + '/__report";\n'
        config += (Path(__file__).with_name('benchmark') / 'autoconfig.js').read_text()
        (served / 'alix-benchmark.cfg').write_text(config)
        for name in ('BenchChild.sys.mjs', 'BenchParent.sys.mjs'):
            shutil.copyfile(Path(__file__).with_name('benchmark') / name, served / name)
        gdb_port = free_port()
        report['gdb_port'] = gdb_port
        event('vm_setup', work=str(work), gdb_port=gdb_port)
        real_qemu = shutil.which('qemu-system-x86_64')
        wrapper = work / 'qemu-boot'
        wrapper.write_text('#!/usr/bin/env python3\nimport os,sys\n' +
            f'a=[v.replace("file=fat:ro:build/boot,", "file=fat:ro:{boot},") for v in sys.argv[1:]]\n' +
            f'os.execv({real_qemu!r}, [{real_qemu!r}]+a)\n')
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env.update(AUDIO_DEV='none', NET_BACKEND='user',
                   NETDUMP=f'-object filter-dump,id=bench,netdev=n0,queue=all,file={output}/network.pcap', QEMU_DEBUG_FLAGS='',
                   QEMU_DATA_IMG=str(disk), QEMU_TIMEOUT_SECONDS=str(args.timeout * (len(args.url) + 2)),
                   QEMU_SERIAL_LOG=str(output / 'runner.log'), QEMU_SERIAL=f'unix:{work}/serial.sock,server,nowait',
                   QEMU_GDB_FLAGS=f'-S -display none -qmp unix:{work}/qmp.sock,server,nowait -gdb tcp:127.0.0.1:{gdb_port}')
        env['MAKEFLAGS'] = env.get('MAKEFLAGS', '') + f' QEMU={wrapper} OVMF_VARS={work}/vars.fd RAM={args.ram} SMP_CORES=8'
        # This is a measurement of built artifacts. Boot a private snapshot
        # without a second make racing an external build over shared .tmp
        # outputs. Missing prerequisites still fail normally.
        frozen = ['boot-volume', 'build/alix.elf', 'build/EFI/BOOT/BOOTX64.EFI']
        frozen.extend(str(path.relative_to(ROOT)) for path in (ROOT / 'build/user').rglob('*')
                      if path.is_file() and path.suffix in ('.elf', '.bin'))
        env['MAKEFLAGS'] += ''.join(' -o ' + path for path in frozen)
        runner = subprocess.Popen([str(ROOT / 'run-via-agent.sh')], cwd=ROOT, env=env,
                                  start_new_session=True, stdout=(output / 'launch.log').open('w'), stderr=subprocess.STDOUT)
        serial = None
        qmp = None
        text = bytearray()
        def wait(predicate, label, timeout=args.timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if predicate():
                    return
                if runner.poll() is not None:
                    raise RuntimeError(f'QEMU stopped during {label}: {runner.returncode}')
                time.sleep(.1)
            raise TimeoutError(label)
        try:
            wait(lambda: (work / 'qmp.sock').exists(), 'QMP socket', 40)
            qmp = QMP(work / 'qmp.sock')
            serial = socket.socket(socket.AF_UNIX)
            serial.connect(str(work / 'serial.sock'))
            def collect():
                with (output / 'serial.log').open('ab', buffering=0) as log:
                    while True:
                        try:
                            data = serial.recv(65536)
                        except OSError:
                            break
                        if not data:
                            break
                        log.write(data)
                        text.extend(data)
            threading.Thread(target=collect, daemon=True).start()
            qmp.call('cont')
            wait(lambda: b'login:' in text, 'login', 60)
            serial.sendall(b'root\r')
            wait(lambda: b'password:' in text, 'password', 10)
            serial.sendall(b'root\r')
            wait(lambda: b'root@alix$' in text and b'dhcp: lease acquired.' in text, 'shell/network', 30)
            configured = re.search(rb'\[sched\] timer_ready hz=(\d+) normal_ms=(\d+) ticks=(\d+)', text)
            if configured:
                report['scheduler_boot'] = dict(zip(('frequency_hz', 'normal_ms', 'normal_ticks'),
                                                    (int(value) for value in configured.groups())))
            def command(value, timeout=45):
                offset = len(text)
                serial.sendall(value.encode() + b'\r')
                wait(lambda: re.search(rb'(?:^|\n)root@alix\$ ', text[offset:]), value, timeout)
            if args.bundle:
                event('bundle_install_start')
                command(f'wget http://10.0.2.2:{server.server_port}/unzip.elf /tmp/zen-unzip.elf')
                command(f'wget http://10.0.2.2:{server.server_port}/zen.zip /tmp/zen-install.zip', 180)
                command('/tmp/zen-unzip.elf --discard-archive /tmp/zen-install.zip /usr/lib/zen', 180)
                event('bundle_install_end')
            command('mkdir /tmp/zenbench')
            command(f'mkdir {profile_path}')
            command(f'wget http://10.0.2.2:{server.server_port}/user.js {profile_path}/user.js')
            command('mkdir /usr/lib/zen/defaults/pref')
            for name, destination in (
                ('benchmark.js', '/usr/lib/zen/defaults/pref/benchmark.js'),
                ('alix-benchmark.cfg', '/usr/lib/zen/alix-benchmark.cfg'),
                ('BenchChild.sys.mjs', '/tmp/zenbench/BenchChild.sys.mjs'),
                ('BenchParent.sys.mjs', '/tmp/zenbench/BenchParent.sys.mjs'),
            ):
                command(f'wget http://10.0.2.2:{server.server_port}/{name} {destination}')
            command(f'wget http://10.0.2.2:{server.server_port}/atk_shell.elf /usr/bin/atk_shell.elf')
            if args.quantum is not None or args.steal:
                settings = work / 'settings.gdb'
                commands = ['file ' + str(boot / 'alix.elf'), f'target remote 127.0.0.1:{gdb_port}']
                if args.quantum is not None:
                    if not 1 <= args.quantum <= 100:
                        raise ValueError('quantum must be 1..100 ticks')
                    commands.append(f'set g_time_slice_ticks={args.quantum}')
                if args.steal:
                    commands.append('set g_sched_steal_enable=1')
                settings.write_text('\n'.join(commands + ['detach']) + '\n')
                with (output / 'settings.log').open('w') as log:
                    subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(settings)], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=15)
            serial.sendall(b'start_video\r')
            wait(lambda: b'video_run_loop start' in text, 'desktop compositor', 30)
            move_mouse_to_terminal(qmp)
            qmp.human('mouse_button 1')
            time.sleep(.2)
            qmp.human('mouse_button 0')
            wait(lambda: re.search(rb'\[process\] finalize [^\r\n]*name=atk_shell ', text), 'desktop terminal', 20)
            time.sleep(.5)
            qmp.type('/usr/lib/zen/zen -no-remote -profile ' + profile_path)
            offset = len(text)
            launched = event('browser_command')
            qmp.key('ret', True)
            time.sleep(.05)
            qmp.key('ret', False)
            wait(lambda: b'[user_atk][resize]' in text[offset:], 'first native window')
            report['first_window_host_seconds'] = event('first_native_window') - launched
            seen = 0
            navigations = {}
            deadline = time.monotonic() + args.timeout * len(args.url) + 60
            complete = False
            while time.monotonic() < deadline:
                markers = list(observations)
                for observed, item in markers[seen:]:
                    data = dict(item)
                    name = data.pop('event')
                    event('browser_' + name, observed_host_seconds=observed, **data)
                    if 'requested_url' in data:
                        data['host_seconds'] = observed - navigations.get(data['index'], observed)
                        report['pages'].append(data)
                        qmp.call('screendump', {'filename': str(output / ('page-' + str(data['index']) + '.ppm'))})
                    elif name == 'navigation':
                        navigations[data['index']] = observed
                    elif name == 'paint':
                        report['paint_events'].append(dict(data, observed_host_seconds=observed))
                        qmp.call('screendump', {'filename': str(output / ('paint-' + str(data['index']) + '.ppm'))})
                    elif name == 'browser_ready':
                        report['browser_ready_host_seconds'] = observed - launched
                    elif name == 'complete':
                        complete = True
                seen = len(markers)
                if complete:
                    break
                if runner.poll() is not None:
                    raise RuntimeError('QEMU stopped during page measurement')
                time.sleep(.1)
            if not complete:
                raise TimeoutError('browser benchmark completion')
            report['faults'] = text.count(b'reason: page_fault')
            report['loads_completed'] = sum(page.get('state') == 'complete' and not page.get('timed_out') and
                                            not page.get('error') and not page.get('error_page') for page in report['pages'])
            report['pages_rendered'] = sum(bool(page.get('paints')) and not page.get('error_page') for page in report['pages'])
            # Snapshot after timing so debugger pauses do not inflate load times.
            snapshot = work / 'snapshot.gdb'
            snapshot.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\nsource ' +
                str(Path(__file__).with_name('benchmark') / 'profile.gdb') + '\ndetach\n')
            with (output / 'kernel-profile.log').open('w') as profile:
                subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(snapshot)], stdout=profile, stderr=subprocess.STDOUT, timeout=20)
            event('finished')
        except BaseException as error:
            report['error'] = f'{type(error).__name__}: {error}'
            event('error', message=report['error'])
            if qmp:
                qmp.call('screendump', {'filename': str(output / 'error.ppm')})
                snapshot = work / 'failure.gdb'
                snapshot.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                    '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\nsource ' +
                    str(Path(__file__).with_name('benchmark') / 'profile.gdb') + '\ndetach\n')
                try:
                    with (output / 'failure-profile.log').open('w') as profile:
                        subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(snapshot)], stdout=profile, stderr=subprocess.STDOUT, timeout=15)
                except subprocess.TimeoutExpired:
                    pass
            raise
        finally:
            (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
            # run-via-agent starts make/QEMU in another process group. Stop
            # that exact guest through QMP before deleting its private disk.
            if qmp:
                try:
                    qmp.call('quit')
                except (OSError, EOFError, json.JSONDecodeError):
                    pass
            if runner.poll() is None:
                try:
                    runner.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(runner.pid, signal.SIGTERM)
                    runner.wait(timeout=5)
            if serial:
                serial.close()
            server.shutdown()


if __name__ == '__main__':
    main()
