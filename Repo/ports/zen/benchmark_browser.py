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
from html import escape
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
import zipfile
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests'))
from quake_gui_liveness_test import move_mouse_to_terminal, ppm_pixels
from audio_qemu_playback_test import mouse_at


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


def wait_native_input_marker(qmp, marker, screenshot, running):
    """Observe the exact disposable marker in real framebuffer pixels."""
    if marker.get('device_pixel_ratio') != 1:
        raise RuntimeError('native-input marker requires devicePixelRatio=1; got ' +
                           repr(marker.get('device_pixel_ratio')))
    colors = marker.get('quadrant_rgb')
    if marker.get('width') != 8 or marker.get('height') != 8 or not isinstance(colors, list) or len(colors) != 4 or any(
            not isinstance(color, list) or len(color) != 3 or any(
                not isinstance(value, int) or not 0 <= value <= 255 for value in color) for color in colors):
        raise RuntimeError('invalid native-input marker geometry or RGB pattern')
    top = bytes(colors[0]) * 4 + bytes(colors[1]) * 4
    bottom = bytes(colors[2]) * 4 + bytes(colors[3]) * 4
    expected_rows = [top] * 4 + [bottom] * 4
    started = time.monotonic()
    deadline = started + 15
    previous_timeout = qmp.socket.gettimeout()
    try:
        while time.monotonic() < deadline:
            if running.poll() is not None:
                raise RuntimeError('QEMU stopped while awaiting native input readiness')
            qmp.socket.settimeout(max(.001, deadline - time.monotonic()))
            qmp.call('screendump', {'filename': str(screenshot)})
            width, height, pixels = ppm_pixels(screenshot)
            candidate = pixels.find(top)
            while candidate >= 0:
                if candidate % 3 == 0:
                    y, x = divmod(candidate // 3, width)
                    if x + 8 <= width and y + 8 <= height and all(
                            pixels[candidate + row * width * 3:candidate + row * width * 3 + 24] == expected
                            for row, expected in enumerate(expected_rows)):
                        observed = time.monotonic()
                        if observed > deadline:
                            raise TimeoutError('native input readiness screenshot exceeded 15 seconds')
                        return {'native_ready_wait_ms': (observed - started) * 1000,
                                'native_marker_screen_x': x, 'native_marker_screen_y': y}, observed
                candidate = pixels.find(top, candidate + 1)
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(.05, remaining))
    except (TimeoutError, socket.timeout) as error:
        raise TimeoutError('native input readiness screenshot exceeded 15 seconds') from error
    finally:
        qmp.socket.settimeout(previous_timeout)
    raise TimeoutError('native input readiness marker not visible within 15 seconds; last frame: ' + str(screenshot))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--url', action='append', default=[])
    parser.add_argument('--page-title', help='override the local calculator title in the disposable served copy')
    parser.add_argument('--scrollbar-check', action='store_true', help='verify a visible native scrollbar and drag it on the local page')
    parser.add_argument('--ram', default='4G')
    parser.add_argument('--net-backend', choices=('user', 'vmnet-shared'), default='user',
                        help='match the guest network backend; default is isolated QEMU user networking')
    parser.add_argument('--collector-host', help='host IPv4 address reachable from vmnet-shared; required for that backend')
    parser.add_argument('--use-default-profile', action='store_true',
                        help='use the cloned disk default profile instead of creating a new profile; may send saved cookies/session state')
    parser.add_argument('--kernel', type=Path, default=ROOT / 'build/alix.elf')
    parser.add_argument('--bundle', type=Path, help='install this Zen ZIP in the disposable disk before measuring')
    parser.add_argument('--quantum', type=int, help='experimental normal-thread quantum, in 10 ms ticks')
    parser.add_argument('--steal', action='store_true', help='enable the optional kernel work stealing')
    parser.add_argument('--timeout', type=int, default=240)
    parser.add_argument('--repeat', type=int, default=1, help='repeat the URL sequence in the same browser')
    parser.add_argument('--input-samples', type=int, default=3, help='real QMP keyboard probes on each local calculator load')
    parser.add_argument('--native-input', action='store_true',
                        help='wait for a changing calculator marker in native pixels before each real key; record readiness separately')
    parser.add_argument('--shutdown-check', action='store_true',
                        help='close Zen through the window manager, shut down from Terminal, and preserve the private disk')
    parser.add_argument('--geometry-check', action='store_true',
                        help='check stationary cursor pixels, drag against the system bar, and shrink the native window before close')
    args = parser.parse_args()
    if args.net_backend != 'user' and not args.collector_host:
        parser.error('--net-backend vmnet-shared requires --collector-host with the host bridge IPv4 address')
    collector_host = args.collector_host or '10.0.2.2'
    import ipaddress
    try:
        collector_host = str(ipaddress.IPv4Address(collector_host))
    except ipaddress.AddressValueError:
        parser.error('--collector-host must be an IPv4 address')
    bind_host = '127.0.0.1' if args.net_backend == 'user' else collector_host
    args.url = args.url or ['https://www.smh.com.au/']
    if args.geometry_check and (not args.shutdown_check or args.url[-1] != 'local'):
        parser.error('--geometry-check requires --shutdown-check and a final --url local')
    if args.scrollbar_check and (args.url != ['local'] or not args.native_input or args.input_samples < 1):
        parser.error('--scrollbar-check requires --url local --native-input and at least one input sample')
    if not 1 <= args.repeat <= 20:
        parser.error('--repeat must be 1..20')
    if not 0 <= args.input_samples <= 20:
        parser.error('--input-samples must be 0..20')
    args.url *= args.repeat
    source = args.data_image.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'disk_source': str(source), 'source_modified': False, 'ram': args.ram,
              'cpus': 8, 'cpu': 'max,+rdrand', 'pages': [], 'paint_events': [], 'input_events': [],
              'quantum_override': args.quantum, 'steal_override': args.steal,
              'net_backend': args.net_backend, 'collector_host': collector_host}
    if args.native_input:
        report.update(native_input=True, native_ready_events=[])
    profile_path = None if args.use_default_profile else '/root/zenbench-' + secrets.token_hex(4)
    report['profile'] = profile_path or 'existing-default'
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
        if args.page_title is not None:
            page = (served / 'test1.htm').read_text()
            page, count = re.subn(r'<title>.*?</title>', lambda _: '<title>' + escape(args.page_title) + '</title>', page, count=1)
            if count != 1:
                raise RuntimeError('local page has no title element')
            (served / 'test1.htm').write_text(page)
        if args.scrollbar_check:
            page = (served / 'test1.htm').read_text()
            page = page.replace('</body>', '<div id="alix-scroll-probe" style="height:4000px;width:2000px;background:linear-gradient(#ffeeee,#ddeeff)">Native scrollbar probe</div></body>')
            (served / 'test1.htm').write_text(page)
        if args.bundle:
            bundle = args.bundle.resolve(strict=True)
            with bundle.open('rb') as stream:
                report['bundle_sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            shutil.copyfile(bundle, served / 'zen.zip')
            shutil.copyfile(ROOT / 'build/user/runtime/unzip.elf', served / 'unzip.elf')
            shutil.copyfile(ROOT / 'build/fonts.zip', served / 'fonts.zip')
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
        server = ThreadingHTTPServer((bind_host, 0), partial(Handler, directory=str(served)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        args.url = [f'http://{collector_host}:{server.server_port}/test1.htm' if url == 'local' else url for url in args.url]
        (served / 'benchmark.js').write_text('pref("general.config.filename", "alix-benchmark.cfg");\npref("general.config.obscure_value", 0);\npref("general.config.sandbox_enabled", false);\n')
        config = '// Native Alix disposable benchmark\nconst ALIX_BENCH_URLS = ' + json.dumps(args.url) + ';\nconst ALIX_BENCH_TIMEOUT = ' + str(args.timeout * 1000) + ';\n'
        config += 'const ALIX_BENCH_COLLECTOR = ' + json.dumps(f'http://{collector_host}:{server.server_port}/__report') + ';\n'
        config += 'const ALIX_BENCH_INPUT_SAMPLES = ' + str(args.input_samples) + ';\n'
        config += 'const ALIX_BENCH_NATIVE_INPUT = ' + json.dumps(args.native_input) + ';\n'
        config += 'const ALIX_BENCH_PAGE_TITLE = ' + json.dumps(args.page_title) + ';\n'
        config += 'const ALIX_BENCH_SCROLLBAR = ' + json.dumps(args.scrollbar_check) + ';\n'
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
        if args.net_backend != 'user':
            # A parallel vmnet guest must not take the running user's MAC/IP.
            nic_mac = '02:' + ':'.join(f'{value:02x}' for value in secrets.token_bytes(5))
            report['nic_mac'] = nic_mac
            script = wrapper.read_text()
            script = script.replace('os.execv(',
                "a=[v.replace('mac=52:54:00:12:34:56', 'mac=" + nic_mac + "') for v in a]\n" + 'os.execv(', 1)
            wrapper.write_text(script)
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env.update(AUDIO_DEV='none', NET_BACKEND=args.net_backend,
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
            wait(lambda: re.search(rb'\[proc\] destroy[^\r\n]*name=startup\b', text),
                 'startup completion', 120)
            if re.search(rb'fstab: mount [^\r\n]*result=failed', text):
                raise RuntimeError('filesystem mount failed; refusing to benchmark a volatile fallback tree')
            configured = re.search(rb'\[sched\] timer_ready hz=(\d+) normal_ms=(\d+) ticks=(\d+)', text)
            if configured:
                report['scheduler_boot'] = dict(zip(('frequency_hz', 'normal_ms', 'normal_ticks'),
                                                    (int(value) for value in configured.groups())))
            def command(value, timeout=45):
                offset = len(text)
                marker = ('__ZENBENCH_' + secrets.token_hex(8) + '__').encode()
                serial.sendall(value.encode() + b'\recho ' + marker + b'\r')
                # A serial kernel line can land between echo's text and LF.
                # Keep the beginning-of-line guard so typed/redrawn commands
                # cannot satisfy completion, but accept an adjacent log prefix.
                pattern = rb'(?:^|[\r\n])' + re.escape(marker) + rb'(?=[\r\n]|\[|$)'
                wait(lambda: re.search(pattern, text[offset:]), value, timeout)
                return bytes(text[offset:])
            if args.bundle:
                event('bundle_install_start')
                command(f'wget http://{collector_host}:{server.server_port}/unzip.elf /tmp/zen-unzip.elf')
                report['installed_files'] = []
                for archive, destination in (('fonts.zip', '/usr/share/fonts'), ('zen.zip', '/usr/lib/zen')):
                    command(f'wget http://{collector_host}:{server.server_port}/{archive} /tmp/zen-install.zip', 180)
                    installed = command('/tmp/zen-unzip.elf --discard-archive /tmp/zen-install.zip ' + destination, 300)
                    statuses = re.findall(rb'\[proc\] destroy[^\r\n]*name=/tmp/zen-unzip\.elf [^\r\n]*wait_status=(\d+)', installed)
                    if statuses != [b'0'] or b'unzip: done' not in installed:
                        raise RuntimeError(archive + ' extraction failed; inspect serial.log')
                    with zipfile.ZipFile(served / archive) as package:
                        for member in package.infolist():
                            if member.is_dir():
                                continue
                            digest = hashlib.sha1(package.read(member)).hexdigest()
                            path = destination + '/' + member.filename
                            checksum = command('sha1sum ' + path, 180)
                            if digest.encode() not in checksum:
                                raise RuntimeError('installed file hash mismatch: ' + path)
                            report['installed_files'].append({'path': path, 'sha1': digest})
                event('bundle_install_end')
            command('mkdir /tmp/zenbench')
            if profile_path is not None:
                command(f'mkdir {profile_path}')
                command(f'wget http://{collector_host}:{server.server_port}/user.js {profile_path}/user.js')
            command('mkdir /usr/lib/zen/defaults/pref')
            for name, destination in (
                ('benchmark.js', '/usr/lib/zen/defaults/pref/benchmark.js'),
                ('alix-benchmark.cfg', '/usr/lib/zen/alix-benchmark.cfg'),
                ('BenchChild.sys.mjs', '/tmp/zenbench/BenchChild.sys.mjs'),
                ('BenchParent.sys.mjs', '/tmp/zenbench/BenchParent.sys.mjs'),
            ):
                command(f'wget http://{collector_host}:{server.server_port}/{name} {destination}')
            command(f'wget http://{collector_host}:{server.server_port}/atk_shell.elf /usr/bin/atk_shell.elf')
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
            qmp.type('/usr/lib/zen/zen -no-remote' + (' -profile ' + profile_path if profile_path is not None else ''))
            initial_snapshot = work / 'initial.gdb'
            initial_snapshot.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\nsource ' +
                str(Path(__file__).with_name('benchmark') / 'profile.gdb') + '\ndetach\n')
            with (output / 'initial-profile.log').open('w') as profile:
                subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(initial_snapshot)], stdout=profile, stderr=subprocess.STDOUT, timeout=20)
            initial_counters = re.search(r'^PERFORMANCE_COUNTERS (.*)$', (output / 'initial-profile.log').read_text(), re.M)
            if initial_counters:
                report['initial_counters'] = json.loads(initial_counters.group(1))
            offset = len(text)
            launched = event('browser_command')
            qmp.key('ret', True)
            time.sleep(.05)
            qmp.key('ret', False)
            wait(lambda: b'[user_atk][resize]' in text[offset:], 'first native window')
            report['first_window_host_seconds'] = event('first_native_window') - launched
            seen = 0
            navigations = {}
            inputs = {}
            native_readiness = {}
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
                    elif name == 'input_ready':
                        if args.native_input:
                            key = (data['index'], data['sample'])
                            screenshot = output / ('native-ready-' + str(key[0]) + '-' + str(key[1]) + '.ppm')
                            gate_started = time.monotonic()
                            try:
                                ready, ready_at = wait_native_input_marker(qmp, data.get('native_marker', {}), screenshot, runner)
                            except (OSError, RuntimeError, ValueError) as error:
                                failure = {'index': key[0], 'sample': key[1], 'error': str(error),
                                           'native_ready_wait_ms': (time.monotonic() - gate_started) * 1000,
                                           'native_ready_screenshot': screenshot.name,
                                           'native_ready_attempt_end_host_after_launch_seconds': time.monotonic() - start - launched,
                                           'selected_tab': data.get('selected_tab'),
                                           'visibility': data.get('visibility'),
                                           'document_focused': data.get('document_focused'),
                                           'focused': data.get('focused'),
                                           'key_to_report_upper_bound_ms': None}
                                report['input_events'].append(failure)
                                event('native_input_readiness_error', **failure)
                                raise
                            ready.update(native_ready_host_after_launch_seconds=ready_at - start - launched,
                                         native_ready_screenshot=screenshot.name,
                                         native_marker=data['native_marker'])
                            native_readiness[key] = ready
                            report['native_ready_events'].append(dict(index=key[0], sample=key[1], **ready))
                            if key == (0, 0):
                                report['first_cold_native_ready_host_upper_bound_seconds'] = ready['native_ready_host_after_launch_seconds']
                            event('native_input_ready', index=key[0], sample=key[1], **ready)
                        inputs[(data['index'], data['sample'])] = time.monotonic() - start
                        qmp.key('ret', True)
                        time.sleep(.05)
                        qmp.key('ret', False)
                    elif name == 'input':
                        if args.native_input:
                            data.update(native_readiness.get((data['index'], data['sample']), {}))
                        injected = inputs.get((data['index'], data['sample']))
                        # Includes the outbound report's network/IPC delay; an
                        # upper bound, distinct from the guest event-to-paint.
                        data['key_to_report_upper_bound_ms'] = (observed - injected) * 1000 if injected is not None else None
                        report['input_events'].append(data)
                        qmp.call('screendump', {'filename': str(output / ('input-' + str(data['index']) + '-' + str(data['sample']) + '.ppm'))})
                    elif name == 'scrollbar_ready':
                        shot = output / 'scrollbar-before.ppm'
                        qmp.call('screendump', {'filename': str(shot)})
                        width, height, pixels = ppm_pixels(shot)
                        best = None
                        expected_height = data['viewport_height'] ** 2 / data['scroll_height']
                        ready = native_readiness[(data['index'], 0)]
                        content_top = ready['native_marker_screen_y'] - ready['native_marker']['inset_css_pixels']
                        for x in range(width - 80, width - 10):
                            run = None
                            for y in range(content_top, min(height, content_top + data['viewport_height'])):
                                matches = all(pixels[(y * width + x + dx) * 3:(y * width + x + dx) * 3 + 3] == b'\xcd\xcd\xcd' for dx in range(3))
                                if matches and run is None: run = y
                                if not matches and run is not None:
                                    if abs(y - run - expected_height) < max(20, expected_height * .2) and (best is None or y - run > best['height']):
                                        best = {'x': x + 1, 'y': run, 'height': y - run}
                                    run = None
                        if best is None or best['height'] < 30:
                            raise RuntimeError('native scrollbar thumb is not visible')
                        report['scrollbar_thumb'] = best
                        mouse_at(qmp, best['x'], best['y'] + best['height'] // 2)
                        time.sleep(.5)
                        qmp.call('screendump', {'filename': str(output / 'scrollbar-hover.ppm')})
                        qmp.human('mouse_button 1')
                        try:
                            time.sleep(.5)
                            qmp.call('screendump', {'filename': str(output / 'scrollbar-pressed.ppm')})
                            for _ in range(2):
                                qmp.human('mouse_move 0 60'); time.sleep(.5)
                            # Keep the drag alive until the guest acknowledges
                            # scrolling, rather than releasing before delayed
                            # content/native input has established capture.
                            deadline = time.monotonic() + 15
                            while not any(value.get('event') == 'scrollbar' and value.get('index') == data['index']
                                          for _, value in observations):
                                if time.monotonic() >= deadline:
                                    raise TimeoutError('native scrollbar drag acknowledgement')
                                qmp.human('mouse_move 0 1'); time.sleep(.25)
                        finally:
                            qmp.human('mouse_button 0')
                        time.sleep(.3)
                        mouse_at(qmp, 600, 500)
                        qmp.call('screendump', {'filename': str(output / 'scrollbar-after.ppm')})
                    elif name == 'scrollbar':
                        report['scrollbar_result'] = data
                        if data.get('error') or data.get('scroll_y', 0) <= data.get('before', 0):
                            raise RuntimeError('native scrollbar drag did not scroll the page')
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
            counters = re.search(r'^PERFORMANCE_COUNTERS (.*)$', (output / 'kernel-profile.log').read_text(), re.M)
            if counters:
                report['performance_counters'] = json.loads(counters.group(1))
                report['workload_counters'] = {key: value - report.get('initial_counters', {}).get(key, 0)
                    for key, value in report['performance_counters'].items()}
            if args.shutdown_check:
                windows_script = work / 'windows.gdb'
                windows_script.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                    '\ntarget remote 127.0.0.1:' + str(gdb_port) + '''\npython
import json
p=gdb.parse_and_eval('g_windows_head'); rows=[]
while int(p):
 w=p.dereference(); owner=w['owner'].dereference(); frame=w['window'].dereference()
 private=(w['window']+1).cast(gdb.lookup_type('atk_window_priv_t').pointer()).dereference()
 rows.append({'name':owner['name'].string(),'pid':int(owner['pid']),'x':int(frame['x']),'y':int(frame['y']),'width':int(frame['width']),'height':int(frame['height']),'pixels':int(w['pixel_bytes']),'title':private['title'].string()});p=w['next']
print('NATIVE_WINDOWS '+json.dumps(rows))
end
detach
''')
                def native_windows(label):
                    windows = subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(windows_script)],
                        capture_output=True, text=True, check=True, timeout=20).stdout
                    (output / (label + '.log')).write_text(windows)
                    return json.loads(re.search(r'^NATIVE_WINDOWS (.*)$', windows, re.M)[1])
                native = native_windows('windows')
                browser = max((w for w in native if 'zen' in w['name']), key=lambda w: w['pixels'])
                terminal = next(w for w in native if 'atk_shell' in w['name'])
                if args.page_title is not None:
                    report['native_title'] = browser['title']
                    if not browser['title'].startswith(args.page_title):
                        raise RuntimeError('native window title was truncated: ' + browser['title'])
                if args.geometry_check:
                    mouse_at(qmp, 1150, 900)
                    # Move focus from Add to the number input, then change
                    # its value so these samples include real new frames.
                    qmp.key('shift', True)
                    for _ in range(2):
                        qmp.key('tab', True); time.sleep(.05); qmp.key('tab', False); time.sleep(.05)
                    qmp.key('shift', False)
                    samples = []
                    for sample in range(12):
                        if sample % 3 == 0:
                            qmp.key('up', True); time.sleep(.05); qmp.key('up', False)
                        shot = output / ('cursor-' + str(sample) + '.ppm')
                        qmp.call('screendump', {'filename': str(shot)})
                        width, _, pixels = ppm_pixels(shot)
                        present = all(tuple(pixels[((900 + y) * width + 1150 + x) * 3:((900 + y) * width + 1150 + x) * 3 + 3]) == (64, 64, 64)
                                      for x, y in ((1, 2), (1, 3), (2, 4), (3, 5)))
                        samples.append(present); time.sleep(.05)
                    if not all(samples):
                        raise RuntimeError('cursor missing from a native refresh sample')
                    mouse_at(qmp, 400, browser['y'] + 14)
                    qmp.human('mouse_button 1'); time.sleep(.15)
                    for _ in range(3):
                        qmp.human('mouse_move 0 -100'); time.sleep(.15)
                    qmp.human('mouse_button 0'); time.sleep(.3)
                    dragged = max((w for w in native_windows('dragged') if w['pid'] == browser['pid']), key=lambda w: w['pixels'])
                    if dragged['y'] < 42:
                        raise RuntimeError('window crossed the system bar')
                    mouse_at(qmp, min(1279, dragged['x'] + dragged['width']), 300)
                    qmp.human('mouse_button 1'); time.sleep(.15)
                    for _ in range(3):
                        qmp.human('mouse_move -100 0'); time.sleep(.15)
                    qmp.human('mouse_button 0'); time.sleep(1)
                    shrunk = max((w for w in native_windows('shrunk') if w['pid'] == browser['pid']), key=lambda w: w['pixels'])
                    if shrunk['width'] >= dragged['width'] - 200:
                        raise RuntimeError('native window did not shrink')
                    qmp.call('screendump', {'filename': str(output / 'shrunk.ppm')})
                    report['geometry'] = {'cursor_samples_present': sum(samples), 'cursor_samples': len(samples),
                                          'dragged': dragged, 'shrunk': shrunk}
                    browser = shrunk
                offset = len(text)
                mouse_at(qmp, min(1270, browser['x'] + browser['width'] - 16), browser['y'] + 14)
                qmp.human('mouse_button 1'); time.sleep(.15); qmp.human('mouse_button 0')
                closed = rb'\[proc\] destroy pid=0x%016X [^\r\n]*wait_status=(\d+)' % browser['pid']
                qmp.call('screendump', {'filename': str(output / 'closed.ppm')})
                if args.geometry_check:
                    width, _, before = ppm_pixels(output / 'shrunk.ppm')
                    _, _, after = ppm_pixels(output / 'closed.ppm')
                    for x, y in ((1150, 200), (1200, 350), (1180, 450)):
                        offset_pixel = (y * width + x) * 3
                        if before[offset_pixel:offset_pixel + 3] != after[offset_pixel:offset_pixel + 3]:
                            raise RuntimeError('pixels outside the shrunken window differ from the desktop')
                    report['geometry']['outside_pixels_match_desktop'] = True
                mouse_at(qmp, max(1, terminal['x'] + 40), max(70, terminal['y'] + 70))
                qmp.human('mouse_button 1'); time.sleep(.15); qmp.human('mouse_button 0')
                qmp.type('shutdown')
                try:
                    qmp.key('ret', True); time.sleep(.05); qmp.key('ret', False)
                except OSError:
                    # ACPI poweroff can close QMP before the Enter key-up.
                    if runner.wait(timeout=5) != 0:
                        raise
                wait(lambda: re.search(closed, text[offset:]), 'browser clean close', 90)
                report['browser_exit_wait_status'] = int(re.search(closed, text[offset:])[1])
                wait(lambda: runner.poll() is not None, 'OS shutdown from Terminal', 90)
                if runner.returncode != 0:
                    raise RuntimeError('OS shutdown returned ' + str(runner.returncode))
                subprocess.run(['cp', '-c' if os.uname().sysname == 'Darwin' else '--reflink=auto',
                    str(disk), str(output / 'shutdown.img')], check=True)
                report['shutdown_completed'] = True
            event('finished')
        except BaseException as error:
            report['error'] = f'{type(error).__name__}: {error}'
            event('error', message=report['error'])
            if qmp:
                try:
                    qmp.call('screendump', {'filename': str(output / 'error.ppm')})
                except (OSError, EOFError, json.JSONDecodeError) as screenshot_error:
                    # Keep the original readiness/measurement error if the
                    # bounded QMP request itself timed out or disconnected.
                    event('failure_screenshot_error', message=str(screenshot_error))
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
