#!/usr/bin/env python3
"""Run the production DNS resolver and receive queue with asynchronous host RX."""
import os,shlex,sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run,function_definition
source=(ROOT/'src/net/dns.c').read_text()
source='\n'.join(line for line in source.splitlines() if not line.startswith('#include'))
for signature,replacement in (
 ('static inline uint64_t dns_irq_save(', 'static inline uint64_t dns_irq_save(void){return 0;}'),
 ('static inline void dns_irq_restore(', 'static inline void dns_irq_restore(uint64_t flags){(void)flags;}')):
 source=source.replace(function_definition(source,signature),replacement)
header='\n'.join(line for line in (ROOT/'include/net/dns.h').read_text().splitlines() if not line.startswith('#include'))
program=r'''
#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#define CHECK(c) do{if(!(c)){fprintf(stderr,"DNS contract line %d: %s\n",__LINE__,#c);abort();}}while(0)
typedef struct {char name[8];bool present,link_up;uint8_t mac[6];uint32_t ipv4_addr;} net_interface_t;
typedef pthread_mutex_t spinlock_t;
static _Thread_local unsigned dns_locked;
static void spinlock_init(spinlock_t *lock){CHECK(!pthread_mutex_init(lock,NULL));}
static void spinlock_lock(spinlock_t *lock){CHECK(!dns_locked);CHECK(!pthread_mutex_lock(lock));++dns_locked;}
static void spinlock_unlock(spinlock_t *lock){CHECK(dns_locked==1);--dns_locked;CHECK(!pthread_mutex_unlock(lock));}
static unsigned live_allocations;
static void *dns_malloc(size_t bytes){CHECK(!dns_locked);void *p=malloc(bytes);if(p)__atomic_add_fetch(&live_allocations,1,__ATOMIC_RELAXED);return p;}
static void dns_free(void *p){CHECK(!dns_locked);if(p){CHECK(__atomic_fetch_sub(&live_allocations,1,__ATOMIC_RELAXED));free(p);}}
static uint64_t timer_ticks(void){struct timespec t;CHECK(!clock_gettime(CLOCK_MONOTONIC,&t));return(uint64_t)t.tv_sec*100+(uint64_t)t.tv_nsec/10000000;}
static uint32_t timer_frequency(void){return 100;}
static void process_yield(void){CHECK(!dns_locked);sched_yield();}
static void serial_printf(const char *format,...){(void)format;}
static void process_debug_log_stack_write(const char *name,void *caller,const void *data,size_t count){(void)name;(void)caller;(void)data;(void)count;}
static net_interface_t interface={.name="test",.present=true,.link_up=true,.ipv4_addr=0x0a00020f};
static bool net_route_next_hop(net_interface_t *preferred,uint32_t ip,net_interface_t **out,uint32_t *next){(void)preferred;*out=&interface;*next=ip;return true;}
static bool net_arp_lookup(uint32_t ip,uint8_t *mac){(void)ip;memset(mac,0x55,6);return true;}
static bool net_arp_send_request(net_interface_t *iface,uint32_t ip){(void)iface;(void)ip;return true;}
static void net_format_ipv4(uint32_t ip,char *out){sprintf(out,"%u.%u.%u.%u",ip>>24,(ip>>16)&255,(ip>>8)&255,ip&255);}
static void net_format_mac(const uint8_t *mac,char *out){(void)mac;strcpy(out,"555555555555");}
typedef struct transmission {struct transmission *next;net_interface_t *iface;size_t length;unsigned char bytes[];} transmission_t;
static pthread_mutex_t tx_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t tx_changed=PTHREAD_COND_INITIALIZER;
static transmission_t *tx_head,*tx_tail;
static bool stopping;
static unsigned transmissions;
static bool net_if_send_copy(net_interface_t *iface,const uint8_t *bytes,size_t length){
 CHECK(!dns_locked);transmission_t *packet=malloc(sizeof(*packet)+length);CHECK(packet);packet->next=NULL;packet->iface=iface;packet->length=length;memcpy(packet->bytes,bytes,length);
 CHECK(!pthread_mutex_lock(&tx_lock));if(tx_tail)tx_tail->next=packet;else tx_head=packet;tx_tail=packet;++transmissions;CHECK(!pthread_cond_signal(&tx_changed));CHECK(!pthread_mutex_unlock(&tx_lock));return true;
}
'''+header+r'''
#define malloc dns_malloc
#define free dns_free
'''+source+r'''
#undef malloc
#undef free
static void h16(unsigned char *p,unsigned n){p[0]=(unsigned char)(n>>8);p[1]=(unsigned char)n;}
static void h32(unsigned char *p,uint32_t n){h16(p,n>>16);h16(p+2,n);}
static void *server(void *unused){
 (void)unused;
 for(;;){
  CHECK(!pthread_mutex_lock(&tx_lock));while(!tx_head&&!stopping)CHECK(!pthread_cond_wait(&tx_changed,&tx_lock));
  transmission_t *request=tx_head;if(request){tx_head=request->next;if(!tx_head)tx_tail=NULL;}bool done=stopping&&!request;CHECK(!pthread_mutex_unlock(&tx_lock));if(done)break;
  const unsigned char *input=request->bytes;CHECK(request->length>=54);
  const unsigned char *question=input+42+12;size_t count=0;
  while(question[count]){CHECK(question[count]<=63&&count+question[count]+1<256);count+=(size_t)question[count]+1;}
  count+=5;size_t dns_length=12+count+32,total=14+20+8+dns_length;
  unsigned char *reply=calloc(1,total);CHECK(reply);memcpy(reply,input,14+20+8);
  memcpy(reply+26,input+30,4);memcpy(reply+30,input+26,4);h16(reply+16,20+8+dns_length);
  memcpy(reply+34,input+36,2);memcpy(reply+36,input+34,2);h16(reply+38,8+dns_length);h16(reply+40,0);
  unsigned char *dns=reply+42;memcpy(dns,input+42,2);h16(dns+2,0x8180);h16(dns+4,1);h16(dns+6,2);memcpy(dns+12,question,count);
  size_t at=12+count;for(unsigned n=0;n<2;++n){h16(dns+at,0xc00c);h16(dns+at+2,1);h16(dns+at+4,1);h32(dns+at+6,60);h16(dns+at+10,4);h32(dns+at+12,0x0a010203+n);at+=16;}
  // Frames with inconsistent lengths/fragments/checksum must not enter RX.
  h16(reply+16,65535);net_dns_handle_frame(request->iface,reply,total);h16(reply+16,20+8+dns_length);
  h16(reply+20,0x2000);net_dns_handle_frame(request->iface,reply,total);h16(reply+20,0);
  h16(reply+40,1);net_dns_handle_frame(request->iface,reply,total);h16(reply+40,0);
  for(unsigned duplicate=0;duplicate<8;++duplicate)net_dns_handle_frame(request->iface,reply,total);
  free(reply);free(request);
 }
 return NULL;
}
typedef struct {char name[64];net_dns_result_t result;bool success;pthread_t thread;} lookup_t;
static void *lookup(void *argument){lookup_t *job=argument;job->success=net_dns_resolve(job->name,NET_DNS_TYPE_A,NULL,&job->result);return NULL;}
int main(void){
 net_dns_init();uint32_t address=0x0a000202;net_dns_set_servers(&address,1);
 uint64_t flags=dns_lock();g_next_port=0xffed;g_next_id=0xfffd;dns_unlock(flags);
 pthread_t *responder=malloc(sizeof(*responder));lookup_t *jobs=calloc(8,sizeof(*jobs));CHECK(responder&&jobs);CHECK(!pthread_create(responder,NULL,server,NULL));
 for(unsigned n=0;n<8;++n){snprintf(jobs[n].name,sizeof(jobs[n].name),"native%u.test",n);CHECK(!pthread_create(&jobs[n].thread,NULL,lookup,&jobs[n]));}
 for(unsigned n=0;n<8;++n){CHECK(!pthread_join(jobs[n].thread,NULL));CHECK(jobs[n].success&&jobs[n].result.has_a&&jobs[n].result.addr_count==2&&jobs[n].result.addrs[0]==0x0a010203&&jobs[n].result.addrs[1]==0x0a010204);}
 unsigned before=transmissions;CHECK(net_dns_resolve(jobs[0].name,NET_DNS_TYPE_A,NULL,&jobs[0].result)&&transmissions==before);
 CHECK(jobs[0].result.status==NET_DNS_STATUS_OK&&!strcmp(jobs[0].result.cname,jobs[0].name));
 CHECK(net_dns_resolve_at(jobs[0].name,NET_DNS_TYPE_A,NULL,0x0a000202,1053,&jobs[0].result)&&transmissions>before);
 before=transmissions;CHECK(net_dns_resolve(jobs[0].name,NET_DNS_TYPE_A,NULL,&jobs[0].result)&&transmissions==before);
 uint64_t old_generation=g_server_generation;net_dns_set_servers(&address,1);
 uint32_t stale_address=0x0a0b0c0d;dns_cache_store_a("stale.test","canonical.test",&stale_address,1,60,old_generation);
 CHECK(!dns_cache_lookup("stale.test",NET_DNS_TYPE_A,&jobs[0].result));
 before=transmissions;CHECK(net_dns_resolve(jobs[0].name,NET_DNS_TYPE_A,NULL,&jobs[0].result)&&transmissions>before);
 uint32_t zero=0;CHECK(dns_add_unique_addr(&zero,&(size_t){0},0));
 CHECK(!pthread_mutex_lock(&tx_lock));stopping=true;CHECK(!pthread_cond_signal(&tx_changed));CHECK(!pthread_mutex_unlock(&tx_lock));CHECK(!pthread_join(*responder,NULL));
 CHECK(!tx_head&&!tx_tail&&!live_allocations);
 for(unsigned n=0;n<NET_DNS_MAX_PENDING;++n)CHECK(!g_pending[n].active&&!g_pending[n].packet_head&&!g_pending[n].packet_tail&&!g_pending[n].packet_count);
 free(jobs);free(responder);puts("DNS_OWNED: PASS workers=8 async_rx=1 addresses=2 bounds=1 duplicate_cleanup=1 cache=1 wrap=1");return 0;
}
'''
previous=os.environ.get('HOST_CC')
try:
 os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
 compile_and_run('dns-owned',program)
finally:
 if previous is None:os.environ.pop('HOST_CC',None)
 else:os.environ['HOST_CC']=previous
print('Production DNS asynchronous receive ownership contracts passed')
