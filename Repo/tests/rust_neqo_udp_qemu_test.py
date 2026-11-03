#!/usr/bin/env python3
"""Actual Neqo UDP over the tested native Quinn/Alix bridge with packet proof."""
import collections,json,re,socketserver,struct,threading,subprocess,hashlib
from cpp_runtime_qemu_test import ROOT,run_native_elf
from udp_owned_qemu_test import Echo,checksum

if __name__=='__main__':
    with socketserver.UDPServer(('127.0.0.1',0),Echo) as server:
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        log=ROOT/'build/test-out/neqo-udp-qemu.log';capture=ROOT/'build/test-out/neqo-udp-network.pcap'
        try:
            run_native_elf('rust_neqo_udp_test.elf',('NEQO_UDP_TEST: PASS cpus=8 datagrams=128 actual_neqo=1 quinn=1 endpoints=1 ecn=1 mtu_probe=1 borrowed=1',),
                log,'Actual Neqo UDP in Alix',180,arguments=(str(server.server_address[1]),),expected_wait_status=0,
                fail_on_missing_markers_at_exit=True,pcap_path=capture)
            ports={int(port):int(cpu) for cpu,port in re.findall(r'NEQO_UDP_ENDPOINT: cpu=(\d+) port=(\d+)',log.read_text())}
            if len(ports)!=8:raise RuntimeError('Missing Neqo endpoints')
            raw=capture.read_bytes();endian='<' if raw[:4]==b'\xd4\xc3\xb2\xa1' else '>';cursor=24;sent=collections.Counter();received={}
            while cursor<len(raw):
                _,_,length,_=struct.unpack_from(endian+'IIII',raw,cursor);cursor+=16;frame=raw[cursor:cursor+length];cursor+=length
                if len(frame)<42 or frame[12:14]!=b'\x08\x00' or frame[23]!=17:continue
                ip=frame[14:];ihl=(ip[0]&15)*4;total=struct.unpack_from('!H',ip,2)[0];udp=ip[ihl:total];source,dest,size,check=struct.unpack_from('!HHHH',udp)
                if dest==server.server_address[1] and source in ports:
                    if (ip[1]&3)!=(ports[source]&3) or checksum(ip[:ihl]) or (check and checksum(ip[12:20]+struct.pack('!BBH',0,17,size)+udp)):
                        raise RuntimeError('Neqo ECN/checksum wire mismatch')
                    sent[source]+=1
                if source==server.server_address[1] and dest in ports:received.setdefault(ports[dest],ip[1]&3)
            if len(sent)!=8 or set(sent.values())!={16}:raise RuntimeError('Incomplete Neqo workload or oversized probe transmitted')
            reported={int(cpu):int(ecn) for cpu,ecn in re.findall(r'NEQO_UDP_META: cpu=(\d+) ecn=(\d+)',log.read_text())}
            if reported!=received:raise RuntimeError('Neqo receive ECN mismatch')
            decoded=subprocess.check_output(['tcpdump','-nn','-vv','-r',str(capture),'udp','and','port',str(server.server_address[1])],text=True,stderr=subprocess.STDOUT)
            capture.with_suffix('.decoded.txt').write_text(decoded)
            log.with_suffix('.acceptance.json').write_text(json.dumps({'scope':'Actual Neqo/Quinn UDP; complete HTTP3 and browser separate','cpus':8,'datagrams':128,
                'wire_ecn_and_endpoints':True,'oversize_probe_not_transmitted':True,'borrowed_socket_owner_survives':True,'boot':json.loads(log.with_suffix('.boot-image.json').read_text()),'capture_sha256':hashlib.sha256(raw).hexdigest()},indent=2)+'\n')
        finally:server.shutdown();thread.join()
