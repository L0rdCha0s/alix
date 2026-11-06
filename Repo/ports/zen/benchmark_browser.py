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
import math
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tests'))
from quake_gui_liveness_test import ppm_pixels
from audio_qemu_playback_test import mouse_at, analyse_wave


class QMP:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.connect(str(path))
        self.file = self.socket.makefile('rwb', buffering=0)
        self.events = []
        self.file.readline()
        self.call('qmp_capabilities')

    def read_message(self):
        line = self.file.readline()
        if not line:
            raise EOFError('QMP disconnected')
        return json.loads(line)

    def call(self, command, arguments=None):
        self.file.write(json.dumps({'execute': command, 'arguments': arguments or {}}).encode() + b'\n')
        while True:
            value = self.read_message()
            if 'event' in value:
                self.events.append(value)
            if 'error' in value:
                raise RuntimeError(value)
            if 'return' in value:
                return value['return']

    execute = call

    def shutdown_event(self, timeout=5):
        deadline = time.monotonic() + timeout
        previous = self.socket.gettimeout()
        try:
            while True:
                shutdown = next((event for event in self.events if event.get('event') == 'SHUTDOWN'), None)
                if shutdown:
                    return shutdown
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.socket.settimeout(remaining)
                try:
                    value = self.read_message()
                except (OSError, EOFError):
                    return None
                if 'event' in value:
                    self.events.append(value)
        finally:
            self.socket.settimeout(previous)

    def human(self, command):
        return self.call('human-monitor-command', {'command-line': command})

    def key(self, key, down):
        self.call('input-send-event', {'events': [
            {'type': 'key', 'data': {'down': down, 'key': {'type': 'qcode', 'data': key}}}
        ]})

    def type(self, text, key_delay=.05):
        names = {' ': 'spc', '/': 'slash', '.': 'dot', '_': 'minus', '-': 'minus'}
        for char in text:
            if char == '_':
                self.key('shift', True)
            key = names.get(char, char)
            self.key(key, True)
            time.sleep(key_delay)
            self.key(key, False)
            if char == '_':
                self.key('shift', False)
            time.sleep(key_delay)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_native_input_marker(qmp, marker, screenshot, running, on_stall=None, stall_after_ms=0):
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
    profiled = False
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
            if on_stall and not profiled and (time.monotonic() - started) * 1000 >= stall_after_ms:
                pause = time.monotonic()
                on_stall()
                deadline += time.monotonic() - pause
                profiled = True
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(.05, remaining))
    except (TimeoutError, socket.timeout) as error:
        raise TimeoutError('native input readiness screenshot exceeded 15 seconds') from error
    finally:
        qmp.socket.settimeout(previous_timeout)
    raise TimeoutError('native input readiness marker not visible within 15 seconds; last frame: ' + str(screenshot))


def capture_stable_corners(qmp, data, output, running):
    """Retain settling observations before comparing the held native phase."""
    fixture = data['corner_fixture']
    x = round(data['native_marker_screen_x'] - fixture['viewport_width'] + 24 + fixture['x'])
    y = round(data['native_marker_screen_y'] - 16 + fixture['y'])
    fw, fh = round(fixture['width']), round(fixture['height'])
    prefix = f"{data['index']}-{data['sample']}"
    screenshot = output / f'input-{prefix}.ppm'
    started = time.monotonic()
    deadline = started + 8
    observations = []
    capture = {'x': x, 'y': y, 'width': fw, 'height': fh,
               'observations': observations, 'required_unchanged_ms': 300,
               'required_identical_samples': 4}
    data['corner_fixture_capture'] = capture
    previous, unchanged_since, identical = None, None, 0
    previous_timeout = qmp.socket.gettimeout()
    try:
        time.sleep(.25)
        while time.monotonic() < deadline:
            if running.poll() is not None:
                raise RuntimeError('QEMU stopped during native corner settling')
            qmp.socket.settimeout(max(.001, deadline - time.monotonic()))
            qmp.call('screendump', {'filename': str(screenshot)})
            width, height, pixels = ppm_pixels(screenshot)
            if not (0 <= x < x + fw <= width and 0 <= y < y + fh <= height):
                raise RuntimeError('shaped-corner fixture is outside native framebuffer')
            region = b''.join(pixels[((y + row) * width + x) * 3:
                                    ((y + row) * width + x + fw) * 3] for row in range(fh))
            if region[:3] != bytes((17, 34, 51)):
                raise RuntimeError('shaped-corner native region does not match its background')
            observed = time.monotonic()
            name = f'corner-settling-{prefix}-{len(observations)}.ppm'
            (output / name).write_bytes(f'P6\n{fw} {fh}\n255\n'.encode() + region)
            row = {'file': name, 'elapsed_ms': (observed - started) * 1000,
                   'pixel_sha256': hashlib.sha256(region).hexdigest()}
            if previous is not None:
                row['different_pixels_from_previous'] = sum(
                    region[i:i+3] != previous[i:i+3] for i in range(0, len(region), 3)) if region != previous else 0
                row['max_channel_delta_from_previous'] = max(abs(a - b) for a, b in zip(region, previous)) if region != previous else 0
            observations.append(row)
            if region != previous:
                unchanged_since, identical = observed, 1
            else:
                identical += 1
            previous = region
            if observed <= deadline and identical >= 4 and observed - unchanged_since >= .3:
                name = f'native-corners-{prefix}.ppm'
                (output / name).write_bytes(f'P6\n{fw} {fh}\n255\n'.encode() + region)
                capture.update(file=name, pixel_sha256=row['pixel_sha256'],
                               settling_ms=(observed - started) * 1000,
                               unchanged_ms=(observed - unchanged_since) * 1000,
                               identical_samples=identical, stable=True)
                return
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
    finally:
        qmp.socket.settimeout(previous_timeout)
    raise TimeoutError('native corner region did not settle within 8 seconds')


def input_clock_bridge(data, injected_host_ms, tick_ms):
    """Fit a host-minus-content clock offset, retaining interval uncertainty."""
    before, after = data.get('clock_before'), data.get('clock_after')
    if not before or not after or before.get('time_origin') != after.get('time_origin') or before.get('time_origin') != data.get('input_time_origin'):
        raise ValueError('input clock calibration crossed documents or is missing')
    margin = 2 * tick_ms
    def interval(record):
        samples = record.get('samples', [])
        if len(samples) != 3:
            raise ValueError('incomplete clock calibration')
        for row in samples:
            if any(not isinstance(row.get(key), (int, float)) or not math.isfinite(row[key])
                   for key in ('guest_send_ms', 'guest_receive_ms', 'host_monotonic_ms')) or row['guest_receive_ms'] < row['guest_send_ms']:
                raise ValueError('invalid clock calibration sample')
        best = min(samples, key=lambda row: row['guest_receive_ms'] - row['guest_send_ms'])
        return [best['host_monotonic_ms'] - best['guest_receive_ms'] - margin,
                best['host_monotonic_ms'] - best['guest_send_ms'] + margin]
    first, last = interval(before), interval(after)
    low, high = max(first[0], last[0]), min(first[1], last[1])
    result = {'assumption': 'constant clock offset between bracketing calibrations',
              'guest_tick_margin_ms': margin, 'before_offset_interval_ms': first,
              'after_offset_interval_ms': last, 'consistent': low <= high,
              'offset_midpoint_change_ms': sum(last) / 2 - sum(first) / 2}
    if low > high:
        result['reason'] = 'bracketing clock intervals do not overlap; latency attribution unavailable'
        return result
    event_ms = data.get('event_time_ms')
    native_ms = data.get('key_to_native_marker_upper_bound_ms')
    if not isinstance(event_ms, (int, float)) or not math.isfinite(event_ms) or not isinstance(native_ms, (int, float)) or not math.isfinite(native_ms):
        raise ValueError('missing event/native observation timestamps')
    if data.get('key_repeat'):
        raise ValueError('controlled input unexpectedly repeated')
    delivery = [event_ms + low - injected_host_ms, event_ms + high - injected_host_ms]
    if delivery[1] < 0:
        result.update(consistent=False, reason='event predates injection under clock model')
        return result
    result.update(host_minus_guest_interval_ms=[low, high],
                  key_to_listener_estimate_ms=[max(0, value) for value in delivery])
    dom_ms = data.get('event_to_dom_observer_ms')
    if isinstance(dom_ms, (int, float)) and math.isfinite(dom_ms):
        native_host_ms = injected_host_ms + native_ms
        presentation = [native_host_ms - event_ms - dom_ms - high,
                        native_host_ms - event_ms - dom_ms - low]
        if presentation[1] < 0:
            result.update(consistent=False, reason='native marker predates mutation under clock model')
            result.pop('key_to_listener_estimate_ms', None)
        else:
            result['dom_to_native_marker_estimate_ms'] = [max(0, value) for value in presentation]
    return result


def swgl_mask_cache_readbacks(serial_text):
    config = [dict(enabled=int(enabled), max_entries=int(entries), max_entry_bytes=int(size))
        for enabled, entries, size in re.findall(
            rb'ALIX_SW_MASK_CACHE_CONFIG,enabled=([01]),max_entries=(\d+),max_entry_bytes=(\d+)', serial_text)]
    stats = [dict(context=context.decode(), enabled=int(enabled), hits=int(hits), misses=int(misses),
                  entries=int(entries), bytes=int(size))
        for context, enabled, hits, misses, entries, size in re.findall(
            rb'ALIX_SW_MASK_CACHE_STATS,context=(0x[0-9a-fA-F]+),enabled=([01]),hits=(\d+),misses=(\d+),entries=(\d+),bytes=(\d+)', serial_text)]
    return config, stats


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
    parser.add_argument('--idle-placement', action='store_true', help='prefer an idle CPU for newly runnable unpinned threads')
    parser.add_argument('--futex-empty-locked', action='store_true', help='disable the empty futex-wake fast path for a matched control')
    parser.add_argument('--opaque-copy', action='store_true', help='evaluate the bounded kernel opaque-pixel copy path')
    parser.add_argument('--present-diagnostics', action='store_true', help='time native window mapping, pixel conversion and presentation; perturbs playback')
    parser.add_argument('--gc-profile-ms', type=int, default=0, help='log native content GC slices exceeding this duration; diagnostic only')
    parser.add_argument('--gc-detail', action='store_true', help='also record verbose GC phase reports in the disposable guest')
    parser.add_argument('--timeout', type=int, default=240)
    parser.add_argument('--repeat', type=int, default=1, help='repeat the URL sequence in the same browser')
    parser.add_argument('--input-samples', type=int, default=3, help='real QMP keyboard probes on each local calculator load')
    parser.add_argument('--diagnostics', action='store_true',
                        help='run bounded content scheduling, actor IPC, layout, canvas, font and allocation diagnostics after input probes')
    parser.add_argument('--media-diagnostics', action='store_true', help='record real HTML media/MSE codec support and media preferences')
    parser.add_argument('--media-observe-seconds', type=int, default=0, help='observe sustained playback and native audio queues for up to 60 seconds')
    parser.add_argument('--media-freeze-profile-ms', type=int, default=0, help='capture live threads after a media frame/progress stall; diagnostic only')
    parser.add_argument('--media-native-probe-ms', type=int, default=0, help='sample live video pixels and CPU registers every 250..5000 ms; diagnostic only')
    parser.add_argument('--media-debug-snapshots', action='store_true', help='sample actual Gecko decoder, sink and queue state during playback')
    parser.add_argument('--media-display-width', type=int, help='display the local video fixture at this CSS width, preserving its aspect ratio')
    parser.add_argument('--media-decoder-logs', action='store_true', help='enable verbose decoder logging; perturbs playback')
    parser.add_argument('--media-network-diagnostics', action='store_true', help='record video HTTP request/response/completion metadata; diagnostic only')
    parser.add_argument('--media-disable-av1', action='store_true', help='diagnostic codec control: disable AV1 in the disposable profile')
    parser.add_argument('--media-local-decode', action='store_true', help='diagnostic control: permit actual local decoders in the disposable profile')
    parser.add_argument('--media-fixture', type=Path, help='bounded local VP9/Opus WebM fixture, played using a trusted native input')
    parser.add_argument('--media-mse', action='store_true', help='append the media fixture through a real Media Source buffer')
    parser.add_argument('--media-live', action='store_true', help='use visible player controls to verify live HTML5 video and native frame changes')
    parser.add_argument('--audio-capture', action='store_true', help='record this guest audio output to audio.wav')
    parser.add_argument('--fault-profile', action='store_true', help='capture fatal browser signal context before process teardown; excludes timing comparisons')
    parser.add_argument('--diagnostic-samples', type=int, default=7, help='3..30 samples per content diagnostic')
    parser.add_argument('--stall-profile-ms', type=int, default=0,
                        help='with native input, pause a stalled response for a live CPU/module snapshot; invalidates timing comparisons')
    parser.add_argument('--stall-profile-limit', type=int, default=3, help='maximum live stall captures, 1..6')
    parser.add_argument('--progress-profile-ms', type=int, default=0,
                        help='snapshot heap/VFS/CPU state after 1000..60000 ms without a browser progress event; contaminates timing')
    parser.add_argument('--thread-self-counts', action='store_true',
                        help='arm optional kernel thread-ID syscall counting during the browser workload; invalidates timing comparisons')
    parser.add_argument('--scheduler-cost', action='store_true',
                        help='arm existing per-thread scheduler stage TSC counters; diagnostic only')
    parser.add_argument('--input-clock-sync', action='store_true',
                        help='with native input, bracket each probe with host/content clock calibration; diagnostic setup perturbs the workload')
    parser.add_argument('--swgl-policy', choices=('default', 'full', 'retained'), default='default',
                        help='controlled Alix software-compositor invalidation policy; full/retained require policy readback from a supporting bundle')
    parser.add_argument('--swgl-mask-cache', choices=('default', 'enabled', 'disabled'), default='default',
                        help='control the native rounded-mask cache; explicit settings require native configuration readback')
    parser.add_argument('--startup-effects', choices=('default', 'quiescent'), default='default',
                        help='retain fresh-profile update effects, or seed only disposable Zen version/build prefs to isolate steady UI work')
    parser.add_argument('--zen-symbols', type=Path, default=ROOT / 'ports/zen/upstream/obj-gecko-alix/dist/bin/zen',
                        help='matching unstripped Zen executable for live loader metadata')
    parser.add_argument('--swgl-profile-info', type=Path,
                        help='matching swgl-profile-info JSON for bounded shader-state reads during live snapshots')
    parser.add_argument('--native-input', action='store_true',
                        help='wait for a changing calculator marker in native pixels before each real key; record readiness separately')
    parser.add_argument('--shaped-corner-check', action='store_true',
                        help='exercise eight CSS corner/mask/shadow variants and export native pixel regions for exact bundle comparisons')
    parser.add_argument('--reference-corners', type=Path,
                        help='with --shaped-corner-check, require exact native RGB matches to this prior result.json')
    parser.add_argument('--corner-channel-tolerance', type=int, choices=(0, 1), default=0,
                        help='reference comparison RGB tolerance; default 0 is exact, 1 accommodates single-level raster rounding and reports raw differences')
    parser.add_argument('--shutdown-check', action='store_true',
                        help='close Zen through the window manager, shut down from Terminal, and preserve the private disk')
    parser.add_argument('--geometry-check', action='store_true',
                        help='check stationary cursor pixels, drag against the system bar, and shrink the native window before close')
    parser.add_argument('--rename-probe', help='on the private clone, move and restore this unloaded large file; verify committed extent relocation through GDB')
    args = parser.parse_args()
    if not 0 <= args.gc_profile_ms <= 60000:
        parser.error('--gc-profile-ms must be 0..60000')
    if args.gc_detail and not args.gc_profile_ms:
        parser.error('--gc-detail requires --gc-profile-ms')
    if args.media_fixture or args.media_live:
        args.media_diagnostics = True
    if args.media_freeze_profile_ms:
        if not (args.media_fixture or args.media_live) or not 1000 <= args.media_freeze_profile_ms <= 10000 or args.fault_profile:
            parser.error('--media-freeze-profile-ms requires a media workload, 1000..10000 ms and no fatal-signal watcher')
        if not args.media_native_probe_ms:
            args.progress_profile_ms = args.progress_profile_ms or args.media_freeze_profile_ms
            args.media_debug_snapshots = True
    if args.media_native_probe_ms and (not args.media_live or not 250 <= args.media_native_probe_ms <= 5000):
        parser.error('--media-native-probe-ms requires --media-live and must be 250..5000')
    if args.net_backend != 'user' and not args.collector_host:
        parser.error('--net-backend vmnet-shared requires --collector-host with the host bridge IPv4 address')
    collector_host = args.collector_host or '10.0.2.2'
    import ipaddress
    try:
        collector_host = str(ipaddress.IPv4Address(collector_host))
    except ipaddress.AddressValueError:
        parser.error('--collector-host must be an IPv4 address')
    bind_host = '127.0.0.1' if args.net_backend == 'user' else collector_host
    args.url = args.url or (['local'] if args.diagnostics else ['https://www.smh.com.au/'])
    if args.geometry_check and (not args.shutdown_check or args.url[-1] != 'local'):
        parser.error('--geometry-check requires --shutdown-check and a final --url local')
    if args.rename_probe and (not args.rename_probe.startswith('/root/') or '..' in args.rename_probe.split('/') or not args.shutdown_check):
        parser.error('--rename-probe requires an absolute /root/ file, no parent traversal, and --shutdown-check')
    if args.scrollbar_check and (args.url != ['local'] or not args.native_input or args.input_samples < 1):
        parser.error('--scrollbar-check requires --url local --native-input and at least one input sample')
    if not 1 <= args.repeat <= 20:
        parser.error('--repeat must be 1..20')
    if not 0 <= args.input_samples <= 20:
        parser.error('--input-samples must be 0..20')
    if not 3 <= args.diagnostic_samples <= 30:
        parser.error('--diagnostic-samples must be 3..30')
    if not 0 <= args.stall_profile_ms <= 5000 or not 1 <= args.stall_profile_limit <= 6:
        parser.error('stall threshold must be 0..5000 ms and capture limit 1..6')
    if args.stall_profile_ms and (not args.native_input or not args.zen_symbols.is_file()):
        parser.error('--stall-profile-ms requires --native-input and an existing --zen-symbols ELF')
    if args.progress_profile_ms and (not 1000 <= args.progress_profile_ms <= 60000 or not args.zen_symbols.is_file() or args.thread_self_counts):
        parser.error('--progress-profile-ms requires 1000..60000, matching Zen symbols, and no --thread-self-counts')
    swgl_info = None
    swgl_info_bytes = None
    if args.swgl_profile_info:
        if not (args.stall_profile_ms or args.progress_profile_ms or args.media_freeze_profile_ms):
            parser.error('--swgl-profile-info requires a live stall/progress snapshot mode')
        swgl_info_bytes = args.swgl_profile_info.read_bytes()
        swgl_info = json.loads(swgl_info_bytes)
        if swgl_info.get('schema') != 'alix_swgl_profile_v1':
            parser.error('unsupported SWGL profile metadata schema')
    if args.input_clock_sync and (not args.native_input or args.input_samples < 1):
        parser.error('--input-clock-sync requires --native-input and at least one input sample')
    if args.shaped_corner_check and (args.url != ['local'] or not args.native_input or args.input_samples < 1):
        parser.error('--shaped-corner-check requires only --url local, --native-input and input samples')
    if args.reference_corners and not args.shaped_corner_check:
        parser.error('--reference-corners requires --shaped-corner-check')
    if args.corner_channel_tolerance and not args.reference_corners:
        parser.error('--corner-channel-tolerance requires --reference-corners')
    if args.media_local_decode and not args.media_diagnostics:
        parser.error('--media-local-decode requires --media-diagnostics')
    if not 0 <= args.media_observe_seconds <= 60 or (args.media_observe_seconds and not (args.media_fixture or args.media_live)):
        parser.error('--media-observe-seconds requires a media workload and must be 0..60')
    if args.media_display_width and (not args.media_fixture or not 160 <= args.media_display_width <= 1024):
        parser.error('--media-display-width requires a fixture and must be 160..1024')
    if args.media_fixture and (args.url != ['local'] or not args.native_input or args.input_samples < 1 or args.media_fixture.stat().st_size > 16 * 1024 * 1024):
        parser.error('--media-fixture requires local native input and a fixture no larger than 16 MiB')
    if args.media_mse and not args.media_fixture:
        parser.error('--media-mse requires --media-fixture')
    if args.media_live and (args.media_fixture or not args.native_input or args.url == ['local']):
        parser.error('--media-live requires an external URL and native input, without a local fixture')
    if args.audio_capture and not args.media_diagnostics:
        parser.error('--audio-capture requires --media-diagnostics')
    if args.fault_profile and not args.zen_symbols.is_file():
        parser.error('--fault-profile requires matching --zen-symbols')
    fixture_video = None
    if args.media_fixture:
        probe = subprocess.check_output(['ffprobe', '-v', 'error', '-select_streams', 'v:0',
            '-show_entries', 'stream=codec_name,width,height,avg_frame_rate', '-of', 'json', str(args.media_fixture)])
        streams = json.loads(probe).get('streams', [])
        if len(streams) != 1 or streams[0].get('codec_name') != 'vp9':
            parser.error('--media-fixture requires an actual VP9 video stream')
        fixture_video = streams[0]
    args.url *= args.repeat
    source = args.data_image.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'disk_source': str(source), 'source_modified': False, 'ram': args.ram,
              'cpus': 8, 'cpu': 'max,+rdrand', 'pages': [], 'paint_events': [], 'input_events': [],
              'quantum_override': args.quantum, 'steal_override': args.steal,
              'idle_placement_override': args.idle_placement,
              'futex_empty_locked': args.futex_empty_locked,
              'opaque_copy_override': args.opaque_copy,
              'present_diagnostics': args.present_diagnostics,
              'gc_profile_ms': args.gc_profile_ms,
              'gc_detail': args.gc_detail,
              'net_backend': args.net_backend, 'collector_host': collector_host}
    report.update(input_protocol='trusted_dom_paint_native_response_v5_dom_fixture' if args.shaped_corner_check else ('trusted_dom_paint_native_response_v4_clock_bridge' if args.input_clock_sync else 'trusted_dom_paint_native_response_v3'), diagnostics=[],
                  diagnostic_protocol='zen_content_diagnostics_v2' if args.diagnostics else None,
                  capture_perturbs_timing=bool(args.stall_profile_ms or args.progress_profile_ms or args.thread_self_counts or args.scheduler_cost or args.input_clock_sync or args.rename_probe or args.media_diagnostics or args.fault_profile or args.present_diagnostics or args.gc_profile_ms or args.media_native_probe_ms or args.media_network_diagnostics),
                  fault_profile=args.fault_profile,
                  progress_profile_ms=args.progress_profile_ms,
                  input_clock_sync=bool(args.input_clock_sync),
                  shaped_corner_check=args.shaped_corner_check,
                  corner_fixture_protocol='swgl_corner_fixture_v2_dom' if args.shaped_corner_check else None,
                  corner_capture_protocol='native_corner_stability_v1' if args.shaped_corner_check else None,
                  swgl_policy=args.swgl_policy, swgl_mask_cache=args.swgl_mask_cache,
                  startup_effects=args.startup_effects, chrome_effects=[],
                  media_diagnostics=[], media_diagnostics_requested=args.media_diagnostics, media_local_decode=args.media_local_decode,
                  media_prepared=[], media_playback=[], media_progress=[], media_debug=[], media_audio_captures=[], media_native_failures=[], media_mse=args.media_mse,
                  media_debug_snapshots=args.media_debug_snapshots,
                  media_network_diagnostics=args.media_network_diagnostics, media_network=[],
                  media_native_probe_ms=args.media_native_probe_ms, media_native_progress=[], media_native_cpu_samples=[],
                  gc_profile=[], gc_detail=[],
                  media_freeze_profile_ms=args.media_freeze_profile_ms,
                  media_observe_seconds=args.media_observe_seconds, media_decoder_logs=args.media_decoder_logs,
                  media_disable_av1=args.media_disable_av1,
                  media_fixture_video=fixture_video,
                  media_live=args.media_live,
                  audio_backend='wav' if args.audio_capture else 'none',
                  thread_self_counts=bool(args.thread_self_counts), scheduler_cost=bool(args.scheduler_cost),
                  media_start_profiles=[], stall_profiles=[],
                  host_load_before=list(os.getloadavg()),
                  evaluator_sha256={str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (Path(__file__), *(Path(__file__).with_name('benchmark') / name
                      for name in ('autoconfig.js', 'BenchChild.sys.mjs', 'BenchParent.sys.mjs', 'profile.gdb', 'stall.gdb', 'fault.gdb', 'corner-fixture.html')))})
    source_stat = source.stat()
    report['source_stat_before'] = {name: getattr(source_stat, name) for name in ('st_ino', 'st_size', 'st_mtime_ns')}
    if args.native_input:
        report.update(native_input=True, native_ready_events=[])
    profile_path = None if args.use_default_profile else '/root/zenbench-' + secrets.token_hex(4)
    report['profile'] = profile_path or 'existing-default'
    if swgl_info:
        report['swgl_profile_info'] = swgl_info
        report['swgl_profile_info_sha256'] = hashlib.sha256(swgl_info_bytes).hexdigest()
        (output / 'swgl-profile-info.json').write_text(json.dumps(swgl_info, indent=2) + '\n')
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
        # Keep the exact address-to-source artifact after the disposable VM
        # directory is removed, even if the workspace kernel is rebuilt later.
        shutil.copyfile(boot / 'alix.elf', output / 'kernel.elf')
        shutil.copyfile(ROOT / 'build/EFI/BOOT/BOOTX64.EFI', boot / 'EFI/BOOT/BOOTX64.EFI')
        shutil.copyfile(ROOT / 'vendor/OVMF_VARS-1024x768.fd', work / 'vars.fd')
        for name in ('profile.gdb', 'stall.gdb', 'fault.gdb'):
            original = Path(__file__).with_name('benchmark') / name
            captured = original.read_bytes()
            if hashlib.sha256(captured).hexdigest() != report['evaluator_sha256'][str(original.relative_to(ROOT))]:
                raise RuntimeError('evaluator changed while its snapshot was captured: ' + name)
            (work / name).write_bytes(captured)
        if args.stall_profile_ms or args.progress_profile_ms or args.media_freeze_profile_ms or args.media_native_probe_ms or args.fault_profile:
            shutil.copyfile(args.zen_symbols, work / 'zen-symbols.elf')
            report['zen_symbols_sha256'] = hashlib.sha256((work / 'zen-symbols.elf').read_bytes()).hexdigest()
        served = work / 'served'
        served.mkdir()
        shutil.copyfile(ROOT / 'build/user/atk_shell.elf', served / 'atk_shell.elf')
        shutil.copyfile(ROOT / 'test1.htm', served / 'test1.htm')
        if args.media_fixture:
            shutil.copyfile(args.media_fixture, served / 'media-fixture.webm')
            report['media_fixture_sha256'] = hashlib.sha256((served / 'media-fixture.webm').read_bytes()).hexdigest()
        if args.shaped_corner_check:
            page = (served / 'test1.htm').read_text()
            fixture = (Path(__file__).with_name('benchmark') / 'corner-fixture.html').read_text()
            if page.count('</body>') != 1:
                raise RuntimeError('local page has no unique body end')
            (served / 'test1.htm').write_text(page.replace('</body>', fixture + '</body>'))
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
        native_input_acks = {}
        rename_probe_ack = threading.Event()
        class Handler(SimpleHTTPRequestHandler):
            def do_GET(self):
                uri = urlsplit(self.path)
                if uri.path == '/__clock':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Cache-Control', 'no-store')
                    payload = json.dumps({'host_monotonic_ms': time.monotonic_ns() / 1e6}).encode()
                    self.send_header('Content-Length', str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                elif uri.path == '/__report':
                    value = json.loads(parse_qs(uri.query)['data'][0])
                    ack = None
                    if args.native_input and value.get('event') == 'input' and value.get('native_response_marker'):
                        ack = threading.Event()
                        native_input_acks[(value['index'], value['sample'])] = ack
                    if value.get('event') == 'rename_probe_moved':
                        ack = rename_probe_ack
                    observations.append((time.monotonic() - start, value))
                    if ack is not None and not ack.wait(25 + 20 * args.stall_profile_limit if args.stall_profile_ms else 25):
                        self.send_error(504, 'native response marker acknowledgement timeout')
                        return
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
        config += 'const ALIX_BENCH_INPUT_CLOCK_SYNC = ' + json.dumps(args.input_clock_sync) + ';\n'
        config += 'const ALIX_BENCH_SWGL_POLICY = ' + json.dumps(args.swgl_policy) + ';\n'
        config += 'const ALIX_BENCH_SWGL_MASK_CACHE = ' + json.dumps(args.swgl_mask_cache) + ';\n'
        config += 'const ALIX_BENCH_STARTUP_EFFECTS = ' + json.dumps(args.startup_effects) + ';\n'
        config += 'const ALIX_BENCH_CLOCK_URL = ' + json.dumps(f'http://{collector_host}:{server.server_port}/__clock') + ';\n'
        config += 'const ALIX_BENCH_DIAGNOSTICS = ' + json.dumps(args.diagnostics) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_DIAGNOSTICS = ' + json.dumps(args.media_diagnostics) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_DECODER_LOGS = ' + json.dumps(args.media_decoder_logs) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_NETWORK_DIAGNOSTICS = ' + json.dumps(args.media_network_diagnostics) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_DISABLE_AV1 = ' + json.dumps(args.media_disable_av1) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_OBSERVE_SECONDS = ' + str(args.media_observe_seconds) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_DEBUG_SNAPSHOTS = ' + json.dumps(args.media_debug_snapshots) + ';\n'
        config += 'const ALIX_BENCH_PRESENT_DIAGNOSTICS = ' + json.dumps(args.present_diagnostics) + ';\n'
        config += 'const ALIX_BENCH_GC_PROFILE_MS = ' + str(args.gc_profile_ms) + ';\n'
        config += 'const ALIX_BENCH_GC_DETAIL = ' + json.dumps(args.gc_detail) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_DISPLAY_WIDTH = ' + json.dumps(args.media_display_width) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_LOCAL_DECODE = ' + json.dumps(args.media_local_decode) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_FIXTURE = ' + json.dumps(f'http://{collector_host}:{server.server_port}/media-fixture.webm' if args.media_fixture else None) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_MSE = ' + json.dumps(args.media_mse) + ';\n'
        config += 'const ALIX_BENCH_MEDIA_LIVE = ' + json.dumps(args.media_live) + ';\n'
        config += 'const ALIX_BENCH_DIAGNOSTIC_SAMPLES = ' + str(args.diagnostic_samples) + ';\n'
        config += 'const ALIX_BENCH_PAGE_TITLE = ' + json.dumps(args.page_title) + ';\n'
        config += 'const ALIX_BENCH_SCROLLBAR = ' + json.dumps(args.scrollbar_check) + ';\n'
        config += 'const ALIX_BENCH_RENAME_PROBE = ' + json.dumps(args.rename_probe) + ';\n'
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
        env.update(AUDIO_DEV=('wav,path=' + str(output / 'audio.wav')) if args.audio_capture else 'none', NET_BACKEND=args.net_backend,
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
        fault_watcher = None
        def stop_fault_watcher():
            if fault_watcher is not None and fault_watcher.poll() is None:
                fault_watcher.send_signal(signal.SIGINT)
                try: fault_watcher.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    fault_watcher.terminate()
                    fault_watcher.wait(timeout=5)
                qmp.call('cont')
        serial = None
        qmp = None
        active_audio_capture = None
        def capture_media_start_profile(index):
            if not args.scheduler_cost:
                return
            sequence = len(report['media_start_profiles'])
            script = work / f'media-start-{sequence}.gdb'
            script.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\nsource ' +
                str(work / 'profile.gdb') + '\nset var g_sched_cost_control.enabled = 1\n' +
                ('set var g_thread_self_profile_enabled = 1\n' if args.thread_self_counts else '') + 'detach\n')
            path = output / f'media-start-profile-{sequence}.log'
            with path.open('w') as stream:
                subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(script)],
                               stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=20)
            row = {'index': index, 'sequence': sequence, 'file': path.name,
                   'host_seconds': time.monotonic() - start}
            contents = path.read_text()
            for label, key in (('SCHEDULER_COST', 'scheduler_cost'), ('PERFORMANCE_COUNTERS', 'counters')):
                match = re.search('^' + label + ' (.*)$', contents, re.M)
                if not match:
                    raise RuntimeError('missing media-start ' + label)
                row[key] = json.loads(match.group(1))
            if not row['scheduler_cost']['enabled']:
                raise RuntimeError('scheduler stage counters were not armed before media start')
            report['media_start_profiles'].append(row)
            event('media_start_profile', index=index, sequence=sequence, file=path.name)
        def start_media_audio(index):
            nonlocal active_audio_capture
            if not args.audio_capture or active_audio_capture is not None:
                return
            path = output / f'media-audio-{index}.wav'
            response = qmp.human(f'wavcapture {path} snd0 48000 16 2')
            if not path.exists():
                raise RuntimeError('native audio capture did not start: ' + response)
            active_audio_capture = {'index': index, 'file': path.name,
                'start_host_seconds': time.monotonic() - start}
            report['media_audio_captures'].append(active_audio_capture)
        def stop_media_audio(check=True):
            nonlocal active_audio_capture
            if active_audio_capture is None:
                return
            row = active_audio_capture
            active_audio_capture = None
            qmp.human('stopcapture 0')
            row['end_host_seconds'] = time.monotonic() - start
            row['analysis'] = analyse_wave(output / row['file'])
            if check and row['analysis']['active_seconds'] < 1:
                raise RuntimeError('native media output contains less than one second of audible PCM')
        text = bytearray()
        def check_storage_failure(label):
            if b'[vfs] sync fail' in text:
                commands = work / 'storage-failure.gdb'
                commands.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                    '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\nsource ' +
                    str(work / 'profile.gdb') + '\ndetach\n')
                report['storage_failure_during'] = label
                report['capture_perturbs_timing'] = True
                with (output / 'storage-failure-profile.log').open('w') as profile:
                    try:
                        subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(commands)],
                                       stdout=profile, stderr=subprocess.STDOUT, timeout=20)
                    finally:
                        if qmp is not None: qmp.call('cont')
                raise RuntimeError('guest writeback failed during ' + label + '; see storage-failure-profile.log')
        def wait(predicate, label, timeout=args.timeout):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                check_storage_failure(label)
                if predicate():
                    return
                if runner.poll() is not None:
                    raise RuntimeError(f'QEMU stopped during {label}: {runner.returncode}')
                time.sleep(.1)
            raise TimeoutError(label)
        def cache_probe(path, label):
            commands = work / 'cache-probe.gdb'
            script = '''import json
parts=PARTS
p=gdb.parse_and_eval("'vfs.c'::root")
for part in parts:
 if not part: continue
 p=p['first_child']
 while int(p) and p['name'].string()!=part: p=p['next_sibling']
 if not int(p): break
row=None
if int(p):
 row={name:int(p[name]) for name in ('disk_id','size','capacity','disk_data_offset')}
 row.update({name:bool(p[name]) for name in ('data_unloaded','disk_meta_dirty','disk_data_dirty','disk_name_dirty')})
print('CACHE_PROBE '+json.dumps(row))
'''.replace('PARTS', repr(path.split('/')))
            commands.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\npython\n' + script + '\nend\ndetach\n')
            try:
                captured = subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(commands)],
                    capture_output=True, text=True, timeout=20, check=True).stdout
            finally:
                qmp.call('cont')
            (output / (label + '.log')).write_text(captured)
            return json.loads(re.search(r'^CACHE_PROBE (.*)$', captured, re.M)[1])
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
            if args.audio_capture:
                wait(lambda: b'[hda] output ready on /dev/audio' in text or b'[hda] /dev/audio registration failed' in text,
                     'native audio device', 30)
                if b'[hda] output ready on /dev/audio' not in text:
                    raise RuntimeError('native audio device failed initialization; playback cannot satisfy audio validation')
            if re.search(rb'fstab: mount [^\r\n]*result=failed', text):
                raise RuntimeError('filesystem mount failed; refusing to benchmark a volatile fallback tree')
            configured = re.search(rb'\[sched\] timer_ready hz=(\d+) normal_ms=(\d+) ticks=(\d+)', text)
            if configured:
                report['scheduler_boot'] = dict(zip(('frequency_hz', 'normal_ms', 'normal_ticks'),
                                                    (int(value) for value in configured.groups())))
            def command(value, timeout=45):
                offset = len(text)
                marker = ('__ZENBENCH_' + secrets.token_hex(8) + '__').encode()
                with (output / 'commands.jsonl').open('a') as log:
                    log.write(json.dumps({'command': value, 'marker': marker.decode(), 'offset': offset,
                        'host_seconds': time.monotonic() - start, 'state': 'start'}) + '\n')
                serial.sendall(value.encode() + b'\recho ' + marker + b'\r')
                # A serial kernel line can land between echo's text and LF.
                # Keep the beginning-of-line guard so typed/redrawn commands
                # cannot satisfy completion, but accept an adjacent log prefix.
                pattern = rb'(?:^|[\r\n])' + re.escape(marker) + rb'(?=[\r\n]|\[|$)'
                def finished_command():
                    found = re.search(pattern, text[offset:])
                    return found and b'root@alix$ ' in text[offset + found.end():]
                wait(finished_command, value, timeout)
                with (output / 'commands.jsonl').open('a') as log:
                    log.write(json.dumps({'marker': marker.decode(), 'host_seconds': time.monotonic() - start,
                        'state': 'complete'}) + '\n')
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
                            checksum = re.sub(rb'\[\d+\.\d+\]\[up=[^\]]+\]\[cpu\d+\][^\r\n]*[\r\n]+', b'', checksum)
                            found = re.search(rb'([0-9a-f]{40})\s+' + re.escape(path.encode()), checksum)
                            if not found:
                                raise RuntimeError('installed file hash output was not parseable: ' + path)
                            if found[1].decode() != digest:
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
            if args.quantum is not None or args.steal or args.opaque_copy or args.idle_placement or args.futex_empty_locked:
                settings = work / 'settings.gdb'
                commands = ['file ' + str(boot / 'alix.elf'), f'target remote 127.0.0.1:{gdb_port}']
                if args.quantum is not None:
                    if not 1 <= args.quantum <= 100:
                        raise ValueError('quantum must be 1..100 ticks')
                    commands.append(f'set g_time_slice_ticks={args.quantum}')
                if args.steal:
                    commands.append('set g_sched_steal_enable=1')
                if args.idle_placement:
                    commands.append('set g_sched_idle_placement_enable=1')
                if args.futex_empty_locked:
                    commands.append('set g_futex_empty_wake_fast_enabled=0')
                if args.opaque_copy:
                    commands.append('set g_video_opaque_copy_enabled=1')
                settings.write_text('\n'.join(commands + ['detach']) + '\n')
                with (output / 'settings.log').open('w') as log:
                    subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(settings)], stdout=log, stderr=subprocess.STDOUT, check=True, timeout=15)
            serial.sendall(b'start_video\r')
            wait(lambda: b'video_run_loop start' in text, 'desktop compositor', 30)
            mouse_at(qmp, 384, 124)
            qmp.human('mouse_button 1')
            time.sleep(.2)
            qmp.human('mouse_button 0')
            wait(lambda: re.search(rb'\[process\] finalize [^\r\n]*name=atk_shell ', text), 'desktop terminal', 20)
            time.sleep(.5)
            qmp.type('/usr/lib/zen/zen -no-remote' + (' -profile ' + profile_path if profile_path is not None else ''))
            initial_snapshot = work / 'initial.gdb'
            initial_snapshot.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\nsource ' +
                str(work / 'profile.gdb') +
                ('\nset var g_thread_self_profile_calls = 0\nset var g_thread_self_profile_enabled = 1' if args.thread_self_counts else '') +
                ('\nset var g_sched_cost_control.enabled = 1' if args.scheduler_cost else '') + '\ndetach\n')
            with (output / 'initial-profile.log').open('w') as profile:
                initial_result = subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(initial_snapshot)], stdout=profile, stderr=subprocess.STDOUT, timeout=20)
                if args.thread_self_counts and initial_result.returncode:
                    raise RuntimeError('failed to arm thread-ID syscall counter')
                if args.scheduler_cost and initial_result.returncode:
                    raise RuntimeError('failed to arm scheduler stage counters')
            initial_counters = re.search(r'^PERFORMANCE_COUNTERS (.*)$', (output / 'initial-profile.log').read_text(), re.M)
            if initial_counters:
                report['initial_counters'] = json.loads(initial_counters.group(1))
            if args.rename_probe:
                before = cache_probe(args.rename_probe, 'rename-before')
                if not before or not before['data_unloaded'] or before['capacity'] or before['size'] <= 65536:
                    raise RuntimeError('rename probe needs an unloaded large file: ' + str(before))
                report['rename_probe'] = {'source': args.rename_probe, 'before': before}
            for label, key in (('KERNEL_HEAP', 'kernel_heap'), ('VFS_CACHE', 'vfs_cache'), ('ALIXFS_MOUNTS', 'mounts'), ('AUDIO_OUTPUT', 'audio_output'), ('NATIVE_RENDERER_PRIORITIES', 'renderer_priorities'), ('NATIVE_COMPOSITOR_PRIORITIES', 'compositor_priorities'), ('NATIVE_AUDIO_PRIORITIES', 'audio_priorities'), ('NATIVE_VSYNC_PRIORITIES', 'vsync_priorities'), ('NATIVE_TIMER_PRIORITIES', 'timer_priorities'), ('SCHEDULER_COST', 'scheduler_cost')):
                value = re.search('^' + label + ' (.*)$', (output / 'initial-profile.log').read_text(), re.M)
                if value: report['initial_' + key] = json.loads(value.group(1))
            offset = len(text)
            browser_launch_offset = offset
            if args.fault_profile:
                script = work / 'fault-watch.gdb'
                fault_source = work / 'fault.gdb'
                script.write_text('file ' + str(boot / 'alix.elf') + '\nadd-symbol-file ' + str(work / 'zen-symbols.elf') +
                    '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\npython fault_output_dir = ' + repr(str(output)) + '\n' +
                    fault_source.read_text().replace('source STALL_SCRIPT_PATH', 'source ' + str(work / 'stall.gdb')))
                fault_watcher = subprocess.Popen(['x86_64-elf-gdb', '-nx', '-q', '-batch', '-x', str(script)],
                    stdout=(output / 'fault-watch.log').open('w'), stderr=subprocess.STDOUT)
                until = time.monotonic() + 20
                while not (output / 'fault-watch.ready').exists():
                    if fault_watcher.poll() is not None or time.monotonic() >= until:
                        raise RuntimeError('fatal-signal watcher did not arm')
                    time.sleep(.1)
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
            native_responses = {}
            def capture_stall(key, pending_frame, reason="native_response"):
                if len(report['stall_profiles']) >= args.stall_profile_limit:
                    return
                number = len(report['stall_profiles'])
                entry = {'number': number, 'index': key[0], 'sample': key[1], 'reason': reason,
                         'after_measurement': reason == 'post_native_probe_mapping'}
                report['stall_profiles'].append(entry)
                pending_copy = output / f'stall-{number}-pending.ppm'
                shutil.copyfile(pending_frame, pending_copy)
                entry['pending_marker_screenshot'] = pending_copy.name
                commands = work / f'stall-{number}.gdb'
                commands.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                    '\nadd-symbol-file ' + str(work / 'zen-symbols.elf') +
                    '\ntarget remote 127.0.0.1:' + str(gdb_port) +
                    ('\npython swgl_profile_info = ' + repr(swgl_info) if swgl_info else '') +
                    ('\nsource ' + str(work / 'profile.gdb') if reason == 'progress_timeout' else '') + '\nsource ' + str(work / 'stall.gdb') + '\ndetach\n')
                log = output / f'stall-{number}.log'
                began = time.monotonic()
                try:
                    with log.open('w') as destination:
                        subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(commands)],
                                       stdout=destination, stderr=subprocess.STDOUT, check=True, timeout=20)
                    matched = re.search(r'^ZEN_STALL_SNAPSHOT_JSON (.*)$', log.read_text(), re.M)
                    if not matched:
                        raise RuntimeError('missing live stall snapshot: ' + str(log))
                    snapshot = json.loads(matched.group(1))
                    if len(snapshot.get('cpus', [])) != 8 or not snapshot.get('threads'):
                        raise RuntimeError('incomplete live stall snapshot: ' + str(log))
                    (output / f'stall-{number}.json').write_text(json.dumps(snapshot, indent=2) + '\n')
                    entry.update(log=log.name, snapshot=f'stall-{number}.json')
                    if any(cpu.get('swgl_shader_state', {}).get('status') == 'module_build_id_mismatch'
                           for cpu in snapshot['cpus']):
                        raise RuntimeError('SWGL shader-state metadata does not match the live library')
                finally:
                    entry['host_pause_ms'] = (time.monotonic() - began) * 1000
                    qmp.call('cont')
                event('live_stall_profile', **entry)
            deadline = time.monotonic() + args.timeout * len(args.url) + 60
            complete = False
            progress_at = time.monotonic()
            media_armed = False
            media_frame_state = {}
            native_probe = None
            while time.monotonic() < deadline:
                fatal = re.search(rb'process: default signal pid=(\d+) tid=(\d+) signo=(4|6|7|8|11)\b[^\r\n]*', text[browser_launch_offset:])
                if fatal:
                    if fault_watcher is not None and fault_watcher.poll() is None:
                        try: fault_watcher.wait(timeout=20)
                        except subprocess.TimeoutExpired: stop_fault_watcher()
                    report['browser_fatal_signal'] = fatal.group().decode('utf-8', 'replace')
                    raise RuntimeError('browser fatal signal: ' + report['browser_fatal_signal'])
                check_storage_failure('browser workload')
                if args.progress_profile_ms and (not args.media_freeze_profile_ms or media_armed) and len(observations) == seen and (time.monotonic() - progress_at) * 1000 >= args.progress_profile_ms and len(report['stall_profiles']) < args.stall_profile_limit:
                    pending_frame = output / 'progress-pending.ppm'
                    qmp.call('screendump', {'filename': str(pending_frame)})
                    capture_stall((-1, -1), pending_frame, 'progress_timeout')
                    progress_at = time.monotonic()
                markers = list(observations)
                for observed, item in markers[seen:]:
                    progress_at = time.monotonic()
                    data = dict(item)
                    name = data.pop('event')
                    event('browser_' + name, observed_host_seconds=observed, **data)
                    if 'requested_url' in data:
                        data['host_seconds'] = observed - navigations.get(data['index'], observed)
                        report['pages'].append(data)
                        qmp.call('screendump', {'filename': str(output / ('page-' + str(data['index']) + '.ppm'))})
                    elif name == 'navigation':
                        native_probe = None
                        navigations[data['index']] = observed
                    elif name == 'paint':
                        report['paint_events'].append(dict(data, observed_host_seconds=observed))
                        qmp.call('screendump', {'filename': str(output / ('paint-' + str(data['index']) + '.ppm'))})
                    elif name == 'startup_effects':
                        report['startup_effects_readback'] = data
                    elif name == 'chrome_effect':
                        report['chrome_effects'].append(data)
                    elif name == 'browser_ready':
                        report['browser_ready_host_seconds'] = observed - launched
                    elif name == 'rename_probe_moved':
                        if not args.rename_probe or data.get('source') != args.rename_probe or data.get('moved') != args.rename_probe + '.alixbench-moved':
                            raise RuntimeError('unexpected rename probe report')
                        until = time.monotonic() + 15
                        attempt = 0
                        while True:
                            moved = cache_probe(data['moved'], 'rename-moved-' + str(attempt))
                            attempt += 1
                            if moved and not any(moved[key] for key in ('disk_meta_dirty', 'disk_data_dirty', 'disk_name_dirty')):
                                break
                            if time.monotonic() >= until:
                                raise RuntimeError('rename probe writeback did not complete')
                            time.sleep(.1)
                        before = report['rename_probe']['before']
                        if not moved['data_unloaded'] or moved['capacity'] or moved['size'] != before['size'] or moved['disk_id'] != before['disk_id'] or moved['disk_data_offset'] == before['disk_data_offset']:
                            raise RuntimeError('rename did not preserve and relocate its unloaded payload: ' + str(moved))
                        report['rename_probe'].update(moved=moved, probes=attempt)
                        rename_probe_ack.set()
                    elif name == 'rename_probe_restored':
                        report['rename_probe']['restored'] = data.get('source') == args.rename_probe
                        if not report['rename_probe']['restored']:
                            raise RuntimeError('rename probe restored a different path')
                    elif name == 'rename_probe_error':
                        raise RuntimeError('rename probe failed: ' + data.get('error', 'unknown error'))
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
                            if args.shaped_corner_check:
                                fixture = data.get('corner_fixture')
                                if not fixture or len(fixture.get('shapes', [])) != 8 or data['native_marker'].get('kind') != 'dom':
                                    raise RuntimeError('missing shaped-corner fixture geometry')
                                ready['corner_fixture'] = fixture
                            native_readiness[key] = ready
                            report['native_ready_events'].append(dict(index=key[0], sample=key[1], **ready))
                            if key == (0, 0):
                                report['first_cold_native_ready_host_upper_bound_seconds'] = ready['native_ready_host_after_launch_seconds']
                            event('native_input_ready', index=key[0], sample=key[1], **ready)
                        if args.media_fixture and data['sample'] == 0:
                            capture_media_start_profile(data['index'])
                            start_media_audio(data['index'])
                            media_armed = True
                        inputs[(data['index'], data['sample'])] = time.monotonic() - start
                        qmp.key('ret', True)
                        time.sleep(.05)
                        qmp.key('ret', False)
                        if args.native_input and data.get('native_response_marker'):
                            key = (data['index'], data['sample'])
                            shot = output / f'native-response-{key[0]}-{key[1]}.ppm'
                            response, observed_at = wait_native_input_marker(qmp, data['native_response_marker'], shot, runner,
                                on_stall=(lambda: capture_stall(key, shot)) if args.stall_profile_ms else None,
                                stall_after_ms=args.stall_profile_ms)
                            native_responses[key] = dict(native_response_wait_ms=response['native_ready_wait_ms'],
                                native_response_screenshot=shot.name,
                                key_to_native_marker_upper_bound_ms=(observed_at - start - inputs[key]) * 1000)
                            event('native_input_response', index=key[0], sample=key[1], **native_responses[key])
                    elif name == 'input':
                        if args.native_input:
                            data.update(native_readiness.get((data['index'], data['sample']), {}))
                        injected = inputs.get((data['index'], data['sample']))
                        # Includes the outbound report's network/IPC delay; an
                        # upper bound, distinct from the guest event-to-paint.
                        data['key_to_report_upper_bound_ms'] = (observed - injected) * 1000 if injected is not None else None
                        if args.native_input and data.get('native_response_marker'):
                            key = (data['index'], data['sample'])
                            try:
                                if key not in native_responses:
                                    raise RuntimeError('native response marker was not observed after key injection')
                                data.update(native_responses[key])
                            finally:
                                if not args.shaped_corner_check: native_input_acks[key].set()
                        report['input_events'].append(data)
                        if args.input_clock_sync:
                            if any(entry.get('reason') == 'progress_timeout' or (entry['index'] == data['index'] and entry['sample'] == data['sample'])
                                   for entry in report['stall_profiles']):
                                data['clock_bridge'] = {'consistent': False, 'reason': 'live debugger paused this probe; latency attribution unavailable'}
                            else:
                                frequency = report.get('scheduler_boot', {}).get('frequency_hz', 100)
                                data['clock_bridge'] = input_clock_bridge(data, (start + injected) * 1000,
                                                                         1000 / frequency if frequency > 0 else 10)
                        qmp.call('screendump', {'filename': str(output / ('input-' + str(data['index']) + '-' + str(data['sample']) + '.ppm'))})
                        if args.shaped_corner_check:
                            try:
                                capture_stable_corners(qmp, data, output, runner)
                            finally:
                                native_input_acks[key].set()
                    elif name == 'media_live_ready':
                        report['media_prepared'].append(data)
                        if data.get('error'):
                            raise RuntimeError('live player preparation failed: ' + json.dumps(data))
                        shot = output / f"live-media-ready-{data['index']}.ppm"
                        ready, _ = wait_native_input_marker(qmp, data['native_marker'], shot, runner)
                        native_readiness[(data['index'], 0)] = ready
                        origin_x = ready['native_marker_screen_x'] - data['viewport_width'] + 24
                        origin_y = ready['native_marker_screen_y'] - 16
                        data['native_marker_readback'] = ready
                        data['native_actions'] = []
                        capture_media_start_profile(data['index'])
                        start_media_audio(data['index'])
                        media_armed = True
                        for action in data['actions']:
                            x, y = round(origin_x + action['x']), round(origin_y + action['y'])
                            data['native_actions'].append({'x': x, 'y': y, 'key': action.get('key'),
                                'host_seconds': time.monotonic() - start})
                            if action.get('key'):
                                qmp.key(action['key'], True); time.sleep(.05); qmp.key(action['key'], False)
                            else:
                                mouse_at(qmp, x, y)
                                qmp.human('mouse_button 1'); time.sleep(.15); qmp.human('mouse_button 0')
                            time.sleep(.3)
                        if args.media_native_probe_ms:
                            rect = data['rect']
                            native_probe = {'index': data['index'], 'x': round(origin_x + rect['x']),
                                'y': round(origin_y + rect['y']), 'width': round(rect['width']),
                                'height': max(1, round(rect['height']) - 36), 'playing': False,
                                'next': 0, 'last_changed': None, 'sha256': None, 'captured': False}
                    elif name == 'media_prepared':
                        report['media_prepared'].append(data)
                        if data.get('error') or data.get('width') != fixture_video['width'] or data.get('height') != fixture_video['height']:
                            raise RuntimeError('media fixture preparation failed: ' + json.dumps(data))
                        if args.media_mse and data.get('download_sha256') != report['media_fixture_sha256']:
                            raise RuntimeError('fetched media fixture hash differs from the supplied bytes')
                    elif name == 'media_progress':
                        report['media_progress'].append(data)
                        if native_probe is not None and native_probe['index'] == data['index']:
                            native_probe['playing'] = bool(data.get('playing') and data.get('frames', 0) > 0 and
                                not data.get('seeking') and not data.get('ended'))
                        index = data['index']
                        if not data.get('playing') or data.get('seeking') or data.get('ended'):
                            media_frame_state.pop(index, None)
                            continue
                        media_armed = True
                        frames = (data['callbacks'], data['frames'] - data['dropped'])
                        previous = media_frame_state.get(index)
                        if previous is None or previous['frames'] != frames:
                            media_frame_state[index] = {'frames': frames, 'since': observed, 'captured': False}
                        elif args.media_freeze_profile_ms and not args.media_native_probe_ms and not previous['captured'] and (observed - previous['since']) * 1000 >= args.media_freeze_profile_ms and len(report['stall_profiles']) < args.stall_profile_limit:
                            shot = output / f"media-freeze-{index}-{len(report['stall_profiles'])}.ppm"
                            qmp.call('screendump', {'filename': str(shot)})
                            capture_stall((index, -1), shot, 'media_no_presented_frames')
                            previous['captured'] = True
                    elif name == 'media_debug':
                        report['media_debug'].append(data)
                    elif name == 'media_network':
                        report['media_network'].append(data)
                    elif name in ('gc_profile_row', 'gc_profile_chunk'):
                        report['gc_profile'].append(data)
                        with (output / 'gc-profile.txt').open('a') as log:
                            log.write(data['text'] if 'text' in data else data['line'] + '\n')
                    elif name in ('gc_detail_row', 'gc_detail_chunk'):
                        report['gc_detail'].append(data)
                        with (output / 'gc-detail.txt').open('a') as log:
                            log.write(data['text'] if 'text' in data else data['line'] + '\n')
                    elif name == 'gc_profile_error':
                        report['gc_profile_error'] = data
                    elif name == 'media_playback':
                        native_probe = None
                        report['media_playback'].append(data)
                        active = data.get('trusted_play') or (args.media_live and data.get('already_playing'))
                        dimensions = data.get('width', 0) > 0 and data.get('height', 0) > 0 if args.media_live else data.get('width') == fixture_video['width'] and data.get('height') == fixture_video['height']
                        if data.get('error') or data.get('protocol') != 'zen_media_playback_v1' or not active or data.get('current_time', 0) < (3 if args.media_live else 1.25) or data.get('presented_callbacks', 0) < 3 or data.get('total_video_frames', 0) < 3 or data.get('paused') or data.get('muted') or data.get('ad_showing') or not dimensions:
                            failure = {'index': data.get('index'), 'error': 'native HTML5 playback failed',
                                'playback_error': data.get('error'), 'trusted_play': data.get('trusted_play'),
                                'current_time': data.get('current_time'), 'frames': data.get('total_video_frames'),
                                'paused': data.get('paused'), 'muted': data.get('muted')}
                            report['media_native_failures'].append(failure)
                            event('native_media_validation_failure', **failure)
                            stop_media_audio(check=False)
                            # Retain the following decoder/MSE report and
                            # post-run kernel snapshot before failing below.
                            continue
                        ready = native_readiness[(data['index'], 0)]
                        rect = data['rect']
                        if data.get('device_pixel_ratio') != 1:
                            raise RuntimeError('native video capture requires devicePixelRatio=1')
                        x = round(ready['native_marker_screen_x'] - rect['viewport_width'] + 24 + rect['x'])
                        y = round(ready['native_marker_screen_y'] - 16 + rect['y'])
                        vw, vh = round(rect['width']), round(rect['height'])
                        regions = []
                        for sample in range(2):
                            shot = output / f"media-{data['index']}-{sample}.ppm"
                            qmp.call('screendump', {'filename': str(shot)})
                            width, height, pixels = ppm_pixels(shot)
                            if not (0 <= x < x + vw <= width and 0 <= y < y + vh <= height):
                                raise RuntimeError('native video region outside framebuffer')
                            region = b''.join(pixels[((y+r)*width+x)*3:((y+r)*width+x+vw)*3] for r in range(vh))
                            regions.append(region)
                            (output / f"media-region-{data['index']}-{sample}.ppm").write_bytes(f'P6\n{vw} {vh}\n255\n'.encode() + region)
                            time.sleep(.4)
                        analyzed = max(1, vh - 36) * vw * 3
                        changed = sum(regions[0][i:i+3] != regions[1][i:i+3] for i in range(0, analyzed, 3))
                        colored = [sum(max(region[i:i+3]) - min(region[i:i+3]) > 32
                                       for i in range(0, analyzed, 3)) for region in regions]
                        data['native_capture'] = {'x': x, 'y': y, 'width': vw, 'height': vh, 'changed_pixels': changed,
                                                  'analysis_height': max(1, vh - 36), 'colored_pixels': colored,
                                                  'pixel_sha256': [hashlib.sha256(region).hexdigest() for region in regions]}
                        if changed < 100 or min(colored) < 1000:
                            report['media_native_failures'].append({'index': data['index'], 'changed_pixels': changed,
                                'colored_pixels': colored, 'error': 'decoded video did not visibly advance in native framebuffer'})
                        stop_media_audio()
                    elif name == 'media_capabilities':
                        report['media_diagnostics'].append(data)
                        if data.get('error') or data.get('protocol') != 'zen_media_capabilities_v1' or len(data.get('types', [])) != 11:
                            raise RuntimeError('incomplete HTML media diagnostics: ' + json.dumps(data))
                    elif name == 'diagnostics':
                        report['diagnostics'].append(data)
                        expected = {'timer_zero_delay', 'animation_frame_wait', 'actor_roundtrip_0',
                                    'actor_roundtrip_4096', 'actor_roundtrip_65536', 'dom_batched_layout_128',
                                    'dom_interleaved_layout_128', 'canvas_fill_and_readback', 'fonts_ready',
                                    'font_shape_and_raster', 'arraybuffer_allocate_touch_1m'}
                        cases = data.get('cases', [])
                        if data.get('error') or len(cases) != len(expected) or {row['name'] for row in cases} != expected or any(
                                row.get('status') != 'OK' or len(row.get('samples_ms', [])) != args.diagnostic_samples or any(
                                    not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0
                                    for value in row.get('samples_ms', [])) for row in cases):
                            raise RuntimeError('incomplete or failed Zen content diagnostics: ' + json.dumps(data))
                        if data.get('protocol') != report['diagnostic_protocol'] or any(
                                len(values) != args.diagnostic_samples or any(
                                    not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 for value in values)
                                for row in cases for values in row.get('phases_ms', {}).values()):
                            raise RuntimeError('invalid Zen diagnostic phase records')
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
                if native_probe is not None and native_probe['playing'] and time.monotonic() >= native_probe['next']:
                    probe = native_probe
                    shot = work / 'native-video-probe.ppm'
                    qmp.call('screendump', {'filename': str(shot)})
                    width, height, pixels = ppm_pixels(shot)
                    x, y, vw, vh = (probe[k] for k in ('x', 'y', 'width', 'height'))
                    if not (0 <= x < x + vw <= width and 0 <= y < y + vh <= height):
                        raise RuntimeError(f'native video probe region outside framebuffer: {(x, y, vw, vh)} in {(width, height)}')
                    region = b''.join(pixels[((y+r)*width+x)*3:((y+r)*width+x+vw)*3] for r in range(vh))
                    signature = hashlib.sha256(region).hexdigest()
                    now = time.monotonic()
                    changed = signature != probe['sha256']
                    if changed:
                        probe.update(sha256=signature, last_changed=now, captured=False)
                    frozen_ms = (now - probe['last_changed']) * 1000
                    row = {'index': probe['index'], 'host_seconds': now-start, 'changed': changed,
                           'unchanged_ms': frozen_ms, 'pixel_sha256': signature}
                    report['media_native_progress'].append(row)
                    event('native_media_probe', **{key: value for key, value in row.items() if key != 'host_seconds'})
                    sampled_at = time.monotonic()
                    registers = qmp.human('info registers -a')
                    cpus = []
                    for match in re.finditer(r'CPU#(\d+)(.*?)(?=CPU#\d+|\Z)', registers, re.S):
                        rip = re.search(r'\bRIP=([0-9a-fA-F]+)', match[2])
                        cr3 = re.search(r'\bCR3=([0-9a-fA-F]+)', match[2])
                        cpl = re.search(r'\bCPL=(\d+)', match[2])
                        if rip and cr3 and cpl:
                            cpus.append({'cpu': int(match[1]), 'rip': hex(int(rip[1], 16)),
                                         'cr3': hex(int(cr3[1], 16)), 'cpl': int(cpl[1])})
                    cpu_sample = {'index': probe['index'], 'host_seconds': sampled_at-start,
                                  'duration_ms': (time.monotonic()-sampled_at)*1000, 'cpus': cpus}
                    report['media_native_cpu_samples'].append(cpu_sample)
                    with (output / 'native-cpu-registers.jsonl').open('a') as log:
                        log.write(json.dumps(dict(cpu_sample, registers=registers)) + '\n')
                    if len(cpus) != 8:
                        raise RuntimeError('native register sampler did not obtain all eight CPUs; raw data preserved')
                    if args.media_freeze_profile_ms and frozen_ms >= args.media_freeze_profile_ms and not probe['captured'] and len(report['stall_profiles']) < args.stall_profile_limit:
                        frame = output / f"native-video-freeze-{probe['index']}-{len(report['stall_profiles'])}.ppm"
                        shutil.copyfile(shot, frame)
                        capture_stall((probe['index'], -2-len(report['stall_profiles'])), frame, 'native_video_pixels_unchanged')
                        probe['captured'] = True
                    probe['next'] = time.monotonic() + args.media_native_probe_ms / 1000
                if runner.poll() is not None:
                    raise RuntimeError('QEMU stopped during page measurement')
                time.sleep(.1)
            if not complete:
                raise TimeoutError('browser benchmark completion')
            stop_fault_watcher()
            if args.media_native_probe_ms and report['media_native_cpu_samples'] and not report['stall_profiles']:
                capture_stall((report['media_native_cpu_samples'][-1]['index'], -99),
                              work / 'native-video-probe.ppm', 'post_native_probe_mapping')
            if args.diagnostics and len(report['diagnostics']) != len(args.url):
                raise RuntimeError('missing Zen content diagnostic results')
            if args.media_diagnostics and len(report['media_diagnostics']) != len(args.url):
                raise RuntimeError('missing HTML media capability results')
            if (args.media_fixture or args.media_live) and len(report['media_playback']) != len(args.url):
                raise RuntimeError('missing native HTML5 playback result')
            startup = report.get('startup_effects_readback', {})
            if startup.get('mode') != args.startup_effects or not startup.get('version') or not startup.get('build_id'):
                raise RuntimeError('missing Zen startup-effect readback')
            if args.startup_effects == 'quiescent' and (
                    startup.get('version') != startup.get('current_version') or
                    startup.get('build_id') != startup.get('current_build_id') or
                    any(row.get('update_sweep_present') or row.get('update_border_present')
                        for row in report['chrome_effects'])):
                raise RuntimeError('quiescent startup effects were not established')
            if args.input_clock_sync and len(report['input_events']) != len(args.url) * args.input_samples:
                raise RuntimeError('clock-bridge mode requires a supported input page and complete probes')
            if args.shaped_corner_check:
                rows = report['input_events']
                expected = {(page, sample) for page in range(len(args.url)) for sample in range(args.input_samples)}
                if len(rows) != len(expected) or {(row['index'], row['sample']) for row in rows} != expected or any(
                        not row.get('trusted') or row.get('error') or row.get('actual') != row.get('expected') or
                        not row.get('corner_fixture_capture') for row in rows):
                    raise RuntimeError('shaped-corner workload requires every trusted input and native capture')
                if args.reference_corners:
                    reference_path = args.reference_corners.resolve(strict=True)
                    reference = json.loads(reference_path.read_text())
                    if reference.get('error') or reference.get('kernel_sha256') != report['kernel_sha256'] or reference.get('corner_fixture_protocol') != report['corner_fixture_protocol'] or reference.get('corner_capture_protocol') != report['corner_capture_protocol'] or reference.get('startup_effects') != report['startup_effects']:
                        raise RuntimeError('corner reference failed or used a different kernel/protocol')
                    references = {(row['index'], row['sample']): row for row in reference['input_events']}
                    if len(reference['input_events']) != len(expected) or set(references) != expected:
                        raise RuntimeError('corner reference has different or incomplete probes')
                    comparisons = []
                    report['corner_reference'] = {'result': str(reference_path),
                        'sha256': hashlib.sha256(reference_path.read_bytes()).hexdigest(),
                        'channel_tolerance': args.corner_channel_tolerance, 'comparisons': comparisons}
                    for row in rows:
                        prior = references[(row['index'], row['sample'])]
                        if not prior.get('trusted') or prior.get('error') or prior.get('actual') != prior.get('expected') or row['corner_fixture'] != prior.get('corner_fixture'):
                            raise RuntimeError('corner reference has different fixture geometry/styles or failed input')
                        capture, previous = row['corner_fixture_capture'], prior['corner_fixture_capture']
                        current_size = ppm_pixels(output / capture['file'])
                        previous_size = ppm_pixels(reference_path.parent / previous['file'])
                        if current_size[:2] != previous_size[:2] or hashlib.sha256(previous_size[2]).hexdigest() != previous['pixel_sha256']:
                            raise RuntimeError('corner reference dimensions/hash mismatch')
                        pixels, old_pixels = current_size[2], previous_size[2]
                        changed = sum(pixels[i:i+3] != old_pixels[i:i+3] for i in range(0, len(pixels), 3))
                        maximum = max(abs(a - b) for a, b in zip(pixels, old_pixels))
                        comparisons.append({'index': row['index'], 'sample': row['sample'], 'different_pixels': changed,
                                            'max_channel_delta': maximum, 'pixels': len(pixels) // 3})
                    if any(row['max_channel_delta'] > args.corner_channel_tolerance for row in comparisons):
                        raise RuntimeError('shaped-corner native RGB differs from reference: ' + json.dumps(comparisons))
            if args.rename_probe and not report.get('rename_probe', {}).get('restored'):
                raise RuntimeError('rename probe did not restore the original path')
            report['faults'] = text.count(b'reason: page_fault')
            report['swgl_policy_readback'] = [dict(redraw_on_invalidation=int(value), width=int(width), height=int(height))
                for value, width, height in re.findall(rb'ALIX_SWGL_POLICY,redraw_on_invalidation=([01]),width=(\d+),height=(\d+)', text)]
            if args.swgl_policy != 'default':
                policy = report['swgl_policy_readback']
                if not policy or any(row['redraw_on_invalidation'] != int(args.swgl_policy == 'full') for row in policy):
                    raise RuntimeError('software compositor policy was not confirmed by the actual bundle')
            report['swgl_mask_cache_config'], report['swgl_mask_cache_stats'] = swgl_mask_cache_readbacks(text)
            if args.swgl_mask_cache != 'default':
                config = report['swgl_mask_cache_config']
                if not config or any(row['enabled'] != int(args.swgl_mask_cache == 'enabled') for row in config):
                    raise RuntimeError('rounded-mask cache setting was not confirmed by the actual bundle')
            report['loads_completed'] = sum(page.get('state') == 'complete' and not page.get('timed_out') and
                                            not page.get('error') and not page.get('error_page') for page in report['pages'])
            report['pages_rendered'] = sum(bool(page.get('paints')) and not page.get('error_page') for page in report['pages'])
            # Snapshot after timing so debugger pauses do not inflate load times.
            snapshot = work / 'snapshot.gdb'
            snapshot.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\nsource ' +
                str(work / 'profile.gdb') + '\ndetach\n')
            with (output / 'kernel-profile.log').open('w') as profile:
                subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(snapshot)], stdout=profile, stderr=subprocess.STDOUT, timeout=20)
            for label, key in (('KERNEL_HEAP', 'kernel_heap'), ('VFS_CACHE', 'vfs_cache'), ('ALIXFS_MOUNTS', 'mounts'), ('AUDIO_OUTPUT', 'audio_output'), ('NATIVE_RENDERER_PRIORITIES', 'renderer_priorities'), ('NATIVE_COMPOSITOR_PRIORITIES', 'compositor_priorities'), ('NATIVE_AUDIO_PRIORITIES', 'audio_priorities'), ('NATIVE_VSYNC_PRIORITIES', 'vsync_priorities'), ('NATIVE_TIMER_PRIORITIES', 'timer_priorities'), ('SCHEDULER_COST', 'scheduler_cost')):
                value = re.search('^' + label + ' (.*)$', (output / 'kernel-profile.log').read_text(), re.M)
                if value: report['final_' + key] = json.loads(value.group(1))
            counters = re.search(r'^PERFORMANCE_COUNTERS (.*)$', (output / 'kernel-profile.log').read_text(), re.M)
            if counters:
                report['performance_counters'] = json.loads(counters.group(1))
                report['workload_counters'] = {key: value - report.get('initial_counters', {}).get(key, 0)
                    for key, value in report['performance_counters'].items()}
            if args.opaque_copy and (report.get('performance_counters', {}).get('g_video_opaque_copy_enabled') != 1 or
                                     report.get('performance_counters', {}).get('g_video_opaque_copy_bytes', 0) <= 0):
                raise RuntimeError('kernel opaque-pixel copy was not confirmed active')
            if args.idle_placement and (report.get('performance_counters', {}).get('g_sched_idle_placement_enable') != 1 or
                                       report.get('performance_counters', {}).get('g_sched_idle_placement_redirects', 0) <= 0):
                raise RuntimeError('kernel idle CPU placement was not confirmed active')
            if args.thread_self_counts:
                measured = report.get('performance_counters', {})
                calls = measured.get('g_thread_self_profile_calls')
                if measured.get('g_thread_self_profile_enabled') != 1 or not isinstance(calls, int) or calls < 0:
                    raise RuntimeError('missing or unarmed thread-ID syscall count capture')
            if args.scheduler_cost and (not report.get('final_scheduler_cost', {}).get('enabled') or
                                       not report['final_scheduler_cost'].get('threads')):
                raise RuntimeError('missing or unarmed scheduler stage counter capture')
            if args.futex_empty_locked and report.get('performance_counters', {}).get('g_futex_empty_wake_fast_enabled') != 0:
                raise RuntimeError('locked futex-wake control was not confirmed')
            if report['media_native_failures']:
                raise RuntimeError('decoded video did not visibly advance in native framebuffer: ' +
                                   json.dumps(report['media_native_failures']))
            if args.shutdown_check:
                windows_script = work / 'windows.gdb'
                windows_script.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                    '\ntarget remote 127.0.0.1:' + str(gdb_port) + '''\npython
import json
p=gdb.parse_and_eval('g_windows_head'); rows=[]
while int(p):
 w=p.dereference(); owner=w['owner'].dereference(); frame=w['window'].dereference()
 private=(w['window']+1).cast(gdb.lookup_type('atk_window_priv_t').pointer()).dereference()
 rows.append({'name':owner['name'].string(),'pid':int(owner['pid']),'x':int(frame['x']),'y':int(frame['y']),'width':int(frame['width']),'height':int(frame['height']),'pixels':int(w['pixel_bytes']),'content_width':int(w['content_width']),'content_height':int(w['content_height']),'surface_generation':int(w['surface_generation']),'title':private['title'].string()});p=w['next']
print('NATIVE_WINDOWS '+json.dumps(rows))
end
detach
''')
                def native_windows(label):
                    try:
                        windows = subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(windows_script)],
                            capture_output=True, text=True, check=True, timeout=20).stdout
                    finally:
                        qmp.call('cont')
                    (output / (label + '.log')).write_text(windows)
                    return json.loads(re.search(r'^NATIVE_WINDOWS (.*)$', windows, re.M)[1])
                native = native_windows('windows')
                browser = max((w for w in native if 'zen' in w['name']), key=lambda w: w['pixels'])
                terminal = next(w for w in native if 'atk_shell' in w['name'])
                def measured_browser(label):
                    matches = [w for w in native_windows(label) if w['pid'] == browser['pid']]
                    if not matches:
                        retired = re.search(rb'\[proc\] destroy pid=0x%016X [^\r\n]*wait_status=(\d+)' % browser['pid'],
                                            text[browser_launch_offset:])
                        status = int(retired[1]) if retired else None
                        report['browser_disappeared_during'] = label
                        report['browser_exit_wait_status'] = status
                        raise RuntimeError('browser window disappeared during ' + label + '; wait status ' + str(status))
                    return max(matches, key=lambda w: w['pixels'])
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
                    dragged = measured_browser('dragged')
                    if dragged['y'] < 42:
                        raise RuntimeError('window crossed the system bar')
                    mouse_at(qmp, min(1279, dragged['x'] + dragged['width']), 300)
                    qmp.human('mouse_button 1'); time.sleep(.15)
                    for _ in range(3):
                        qmp.human('mouse_move -100 0'); time.sleep(.15)
                    resize_released = time.monotonic()
                    qmp.human('mouse_button 0')
                    resize_deadline = resize_released + 15
                    probes = 0
                    while True:
                        shrunk = measured_browser('shrunk-' + str(probes))
                        probes += 1
                        target_w = dragged['content_width'] - (dragged['width'] - shrunk['width'])
                        target_h = dragged['content_height'] - (dragged['height'] - shrunk['height'])
                        if shrunk['width'] < dragged['width'] - 200 and target_w > 0 and target_h > 0 and \
                                shrunk['content_width'] == target_w and shrunk['content_height'] == target_h and \
                                shrunk['pixels'] == target_w * target_h * 4:
                            break
                        if time.monotonic() >= resize_deadline:
                            report['geometry'] = {'dragged': dragged, 'shrunk': shrunk, 'resize_probes': probes}
                            raise RuntimeError('native client surface did not acknowledge resized bounds')
                        time.sleep(.05)
                    report['geometry'] = {'cursor_samples_present': sum(samples), 'cursor_samples': len(samples),
                                          'dragged': dragged, 'shrunk': shrunk, 'resize_probes': probes,
                                          'release_to_surface_observation_upper_ms': (time.monotonic() - resize_released) * 1000,
                                          'resize_observation_includes_debugger_pauses': True}
                    if args.native_input and report['input_events']:
                        last = report['input_events'][-1]
                        if last.get('native_response_marker'):
                            marker, observed = wait_native_input_marker(qmp, last['native_response_marker'], output / 'resize-marker.ppm', runner)
                            x, y = marker['native_marker_screen_x'], marker['native_marker_screen_y']
                            if not (shrunk['x'] <= x < shrunk['x'] + shrunk['width'] and shrunk['y'] <= y < shrunk['y'] + shrunk['height']):
                                raise RuntimeError('resized page marker lies outside its window')
                            if last['native_marker_screen_x'] >= shrunk['x'] + shrunk['width'] and x >= last['native_marker_screen_x']:
                                raise RuntimeError('page marker did not relocate after shrinking')
                            report['geometry'].update(resized_page_marker={'x': x, 'y': y},
                                release_to_page_marker_upper_ms=(observed - resize_released) * 1000)
                    qmp.call('screendump', {'filename': str(output / 'shrunk.ppm')})
                    browser = shrunk
                offset = len(text)
                mouse_at(qmp, min(1270, browser['x'] + browser['width'] - 16), browser['y'] + 14)
                close_injected = time.monotonic()
                qmp.human('mouse_button 1'); time.sleep(.15); qmp.human('mouse_button 0')
                event('native_close_injected', pid=browser['pid'])
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
                wait(lambda: re.search(closed, text[offset:]), 'browser clean close', 90)
                report['browser_exit_wait_status'] = int(re.search(closed, text[offset:])[1])
                report['close_to_process_retirement_upper_ms'] = (time.monotonic() - close_injected) * 1000
                if report['browser_exit_wait_status'] != 0:
                    raise RuntimeError('browser close returned wait status ' + str(report['browser_exit_wait_status']))
                launcher = re.search(rb'\[process\] alloc detail [^\r\n]*name=shell_exec pid=0x([0-9A-Fa-f]+)',
                                     text[browser_launch_offset:])
                if not launcher:
                    raise RuntimeError('missing Terminal launch job identity')
                launcher_pid = int(launcher[1], 16)
                launcher_done = rb'\[proc\] destroy pid=0x%016X name=shell_exec\b' % launcher_pid
                wait(lambda: re.search(launcher_done, text[browser_launch_offset:]), 'Terminal launch job retirement', 90)
                report['terminal_launch_job_retired'] = launcher_pid
                # Retirement can exercise a different scheduler/allocator path
                # from painting. Capture it after both jobs have quiesced;
                # these debugger pauses are outside the latency interval above.
                post_close = work / 'post-close.gdb'
                post_close.write_text('set pagination off\nfile ' + str(boot / 'alix.elf') +
                    '\ntarget remote 127.0.0.1:' + str(gdb_port) + '\nsource ' +
                    str(work / 'profile.gdb') + '\ndetach\n')
                try:
                    with (output / 'post-close-profile.log').open('w') as profile:
                        subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(post_close)],
                                       stdout=profile, stderr=subprocess.STDOUT, timeout=30, check=True)
                finally:
                    qmp.call('cont')
                profile_text = (output / 'post-close-profile.log').read_text()
                for label, key in (('KERNEL_HEAP', 'kernel_heap'), ('VFS_CACHE', 'vfs_cache'),
                                   ('PERFORMANCE_COUNTERS', 'performance_counters'), ('AUDIO_OUTPUT', 'audio_output')):
                    found = re.search('^' + label + r' (.*)$', profile_text, re.M)
                    if found:
                        report['post_close_' + key] = json.loads(found[1])
                mouse_at(qmp, max(1, terminal['x'] + 40), max(70, terminal['y'] + 70))
                qmp.human('mouse_button 1'); time.sleep(.15); qmp.human('mouse_button 0')
                # Final console output can outlive the native window. Start
                # from an empty editable line after the command has retired.
                for _ in range(16):
                    qmp.key('backspace', True); time.sleep(.12)
                    qmp.key('backspace', False); time.sleep(.12)
                qmp.type('shutdown', key_delay=.12)
                try:
                    qmp.key('ret', True); time.sleep(.05); qmp.key('ret', False)
                except (OSError, EOFError):
                    # ACPI poweroff can close QMP before the Enter key-up.
                    if runner.wait(timeout=5) != 0:
                        raise
                wait(lambda: runner.poll() is not None, 'OS shutdown from Terminal', 90)
                if runner.returncode != 0:
                    raise RuntimeError('OS shutdown returned ' + str(runner.returncode))
                report['shutdown_event'] = qmp.shutdown_event()
                if not report['shutdown_event'] or report['shutdown_event'].get('data') != {'guest': True, 'reason': 'guest-shutdown'}:
                    raise RuntimeError('missing QMP guest-originated shutdown event')
                subprocess.run(['cp', '-c' if os.uname().sysname == 'Darwin' else '--reflink=auto',
                    str(disk), str(output / 'shutdown.img')], check=True)
                report['shutdown_completed'] = True
            event('finished')
        except BaseException as error:
            report['error'] = f'{type(error).__name__}: {error}'
            event('error', message=report['error'])
            try: stop_fault_watcher()
            except (OSError, EOFError, subprocess.TimeoutExpired): pass
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
                    str(work / 'profile.gdb') + '\ndetach\n')
                try:
                    with (output / 'failure-profile.log').open('w') as profile:
                        subprocess.run(['x86_64-elf-gdb', '-q', '-batch', '-x', str(snapshot)], stdout=profile, stderr=subprocess.STDOUT, timeout=15)
                except subprocess.TimeoutExpired:
                    pass
                failure_log = output / 'failure-profile.log'
                if failure_log.exists():
                    profile_text = failure_log.read_text()
                    for label, key in (('KERNEL_HEAP', 'kernel_heap'), ('VFS_CACHE', 'vfs_cache'),
                                       ('PERFORMANCE_COUNTERS', 'performance_counters'), ('AUDIO_OUTPUT', 'audio_output')):
                        found = re.search('^' + label + r' (.*)$', profile_text, re.M)
                        if found:
                            report['failure_' + key] = json.loads(found[1])
                    halt = re.search(r'\bfatal \(msg=[^\n]*?"([^"\n]+)"', profile_text)
                    if halt:
                        report['failure_kernel_fatal'] = halt[1]
                        event('kernel_fatal_observed', message=halt[1])
            raise
        finally:
            try: stop_media_audio(check=False)
            except (OSError, EOFError, ValueError): pass
            try: stop_fault_watcher()
            except (OSError, EOFError, subprocess.TimeoutExpired): pass
            rename_probe_ack.set()
            for ack in native_input_acks.values():
                ack.set()
            report['host_load_after'] = list(os.getloadavg())
            report['swgl_mask_cache_config'], report['swgl_mask_cache_stats'] = swgl_mask_cache_readbacks(text)
            source_after = source.stat()
            report['source_stat_after'] = {name: getattr(source_after, name) for name in ('st_ino', 'st_size', 'st_mtime_ns')}
            report['source_stat_changed_during_run'] = report['source_stat_before'] != report['source_stat_after']
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
