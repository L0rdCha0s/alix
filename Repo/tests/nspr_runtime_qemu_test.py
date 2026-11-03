#!/usr/bin/env python3
from cpp_runtime_qemu_test import ROOT,run_native_elf
import socketserver
import threading

class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        value=b''
        while len(value)<11:
            part=self.request.recv(11-len(value))
            if not part:break
            value+=part
        if value!=b'native-nspr':raise RuntimeError('incorrect NSPR TCP gather payload')
        self.request.sendall(value)

if __name__=='__main__':
    library=ROOT/'ports/zen/upstream/obj-gecko-alix/dist/bin/libnspr4.so'
    with socketserver.ThreadingTCPServer(('127.0.0.1',0),Echo) as server:
        server.daemon_threads=True
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            run_native_elf('nspr_runtime_test.elf',
                ('NSPR_RUNTIME_CHILD: PASS environment=1 initialized=1',
                 'NSPR_RUNTIME_TEST: PASS cpus=8 updates=512 threads=1 locks=1 condvars=1 once=1 tls_dtors=8 environment=1 writev=1 tcp=1 poll=1 events=1 maps=1 spawn=1 wait_daemon=1 cleanup=1',),
                ROOT/'build/test-out/nspr-runtime-qemu.log','Complete native NSPR runtime',160,
                arguments=(str(server.server_address[1]),),input_files=((library.name,library),),
                pcap_path=ROOT/'build/test-out/nspr-runtime-network.pcap',
                expected_wait_status=0,fail_on_missing_markers_at_exit=True)
        finally:
            server.shutdown();thread.join()
