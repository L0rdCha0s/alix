#!/usr/bin/env python3
"""Verify the owned per-process syscall ABI in an ordinary eight-CPU Alix guest."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import re
import os
import subprocess
import sys
import threading
sys.dont_write_bytecode=True
from cpp_runtime_qemu_test import run_native_elf
from tcp_owned_qemu_test import verify_connection
ROOT=Path(__file__).resolve().parents[1]

def main():
    previous=os.environ.get('SCHEDULER_WAKE_SELFTEST')
    requests=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_args):pass
        def do_GET(self):
            if self.path!='/private':self.send_error(404);return
            requests.append(self.path)
            body=bytes((index*73+19)&255 for index in range(16384))
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);server.daemon_threads=True
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    try:
        os.environ['SCHEDULER_WAKE_SELFTEST']='1'
        subprocess.run(['make','-W','src/kernel/kernel.c','all','SCHEDULER_WAKE_SELFTEST=1',
                        'build/user/private_fd_test.elf','build/user/thread_tls_test.elf'],cwd=ROOT,check=True)
        log=ROOT/'build/test-out/private-fd-qemu.log';capture=ROOT/'build/test-out/private-fd-network.pcap'
        run_native_elf('private_fd_test.elf',
            ('PRIVATE_FD_TEST: PASS workers=8 mask=0xFF records=512 dup=1 flags=1 capacity256=1 no_fallback=1 failed_truncate_preserved=1 HTTP=16384 capture_once=1',),
            log,'Owned private file/stdio/TCP descriptors',timeout_seconds=120,arguments=(str(server.server_port),),
            forbidden_markers=('PRIVATE_FD_TEST: FAIL','SCHEDULER_WAKE_TEST: FAIL'),pcap_path=capture,
            boot_markers=('SCHEDULER_WAKE_TEST: PASS stale_park=32 runnable_preserved=1 peer_progress=1 retained_join=1',))
        serial=log.read_text(errors='replace')
        if serial.count('PRIVATE_STDIO_ONCE')!=1:raise RuntimeError('private console output was duplicated')
        if 'PRIVATE_CAPTURE_ONLY' in serial:raise RuntimeError('private terminal capture leaked to the global console')
        if requests!=['/private']:raise RuntimeError(f'unexpected private HTTP requests: {requests!r}')
        result=subprocess.run(['tcpdump','-nn','-tt','-S','-r',str(capture),'tcp','port',str(server.server_port)],
                              check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        (ROOT/'build/ports/zen/private-fd-packets.txt').write_text(result.stdout)
        packets=[]
        for line in result.stdout.splitlines():
            match=re.match(r'^\S+ IP (\S+) > (\S+): Flags \[([^]]+)\], (.*)$',line)
            if match:packets.append(match.groups())
        connections={(packet[0],packet[1]) for packet in packets if packet[2]=='S'}
        if len(connections)!=1 or sum(verify_connection(packets,*pair) for pair in connections)!=1:
            raise RuntimeError('private TCP capture did not prove one complete HTTP/FIN/ACK exchange')
        run_native_elf('thread_tls_test.elf',('THREAD_TLS_TEST: PASS',),ROOT/'build/test-out/wake-park-tls-qemu.log',
                      'Wake-before-park fix and eight-CPU TLS',timeout_seconds=90,
                      boot_markers=('SCHEDULER_WAKE_TEST: PASS stale_park=32 runnable_preserved=1 peer_progress=1 retained_join=1',),
                      forbidden_markers=('SCHEDULER_WAKE_TEST: FAIL','THREAD_TLS_TEST: FAIL'))
        print('Private descriptor native acceptance PASS: stdio, shared offsets, flags, full-table integrity, TCP and capture')
    finally:
        server.shutdown();server.server_close();worker.join(timeout=5)
        if previous is None:os.environ.pop('SCHEDULER_WAKE_SELFTEST',None)
        else:os.environ['SCHEDULER_WAKE_SELFTEST']=previous
        subprocess.run(['make','-W','src/kernel/kernel.c','all','SCHEDULER_WAKE_SELFTEST=0'],cwd=ROOT,check=True)
        symbols=subprocess.check_output(['x86_64-elf-nm','--defined-only','build/alix.elf'],cwd=ROOT,text=True)
        if any(line.split()[-1:]==['scheduler_wake_boot_test'] for line in symbols.splitlines()):
            raise RuntimeError('ordinary kernel still contains wake-before-park boot test')
    return 0

if __name__=='__main__':
    try:sys.exit(main())
    except (OSError,RuntimeError,subprocess.SubprocessError) as error:
        print(f'Private descriptor acceptance failed: {error}',file=sys.stderr);sys.exit(1)
