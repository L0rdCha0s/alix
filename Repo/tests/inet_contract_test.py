#!/usr/bin/env python3
"""Compare native IPv4 conversion against host libc, with strict failure checks."""
import os,re,sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run
source=(ROOT/'user/lib/inet.c').read_text()
source='\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
for name in ('inet_pton','inet_ntop','htons','ntohs','htonl','ntohl','in6addr_any','in6addr_loopback'):
    source=re.sub(r'\b'+name+r'\b','native_'+name,source)
program=r'''
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#define TTF_HOST_BUILD 1
'''+f'#include "{ROOT / "include/endian.h"}"\n'+r'''
#define CHECK(c) do{if(!(c)){fprintf(stderr,"inet contract line %d: %s\n",__LINE__,#c);abort();}}while(0)
'''+source+r'''
int main(void) {
    char *actual=malloc(64),*expected=malloc(64);CHECK(actual&&expected);
    uint32_t value=0x1256b9ef;
    for(unsigned i=0;i<20000;++i){
        value=value*1664525u+1013904223u;
        uint32_t network=htonl(value),parsed=0;
        CHECK(inet_ntop(AF_INET,&network,expected,64));
        CHECK(native_inet_ntop(AF_INET,&network,actual,64)==actual&&!strcmp(actual,expected));
        CHECK(native_inet_pton(AF_INET,actual,&parsed)==1&&parsed==network);
        CHECK(native_htonl(value)==htonl(value)&&native_ntohl(network)==value);
        CHECK(native_htons((uint16_t)value)==htons((uint16_t)value)&&native_ntohs(htons((uint16_t)value))==(uint16_t)value);
    }
    const char *bad[]={"", "1", "1.2.3", "1.2.3.4.5", "256.1.2.3", "1..2.3", "01.2.3.4", "1.002.3.4", "1.2.3.4 ", " 1.2.3.4", "-1.2.3.4", "0xff.2.3.4", "1.2.3.9999"};
    for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);++i){uint32_t parsed=0xdeadbeef;errno=EBUSY;CHECK(!native_inet_pton(AF_INET,bad[i],&parsed)&&parsed==0xdeadbeef&&errno==EBUSY);}
    uint32_t network=0xffffffff,parsed=0xdeadbeef;
    memset(actual,0x5a,64);CHECK(!native_inet_ntop(AF_INET,&network,actual,15)&&errno==ENOSPC&&actual[0]==0x5a);
    CHECK(native_inet_ntop(AF_INET,&network,actual,16)==actual&&!strcmp(actual,"255.255.255.255")&&actual[16]==0x5a);
    CHECK(native_inet_pton(AF_INET6,"::1",&parsed)==-1&&errno==EAFNOSUPPORT&&parsed==0xdeadbeef);
    CHECK(!native_inet_ntop(AF_INET6,&network,actual,64)&&errno==EAFNOSUPPORT);
    free(expected);free(actual);puts("INET: PASS comparisons=20000 strict_input=1 failed_output_unchanged=1 bounds=1");return 0;
}
'''
compile_and_run('inet-conversion',program)
print('Native IPv4 conversion: 20,000 host comparisons, strict input and output bounds passed')
