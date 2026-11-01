#!/usr/bin/env python3
"""Exercise production libc address lookup, allocation rollback and TLS state."""
import os,re,shlex,sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run
header=(ROOT/'include/netdb.h').read_text().split('#else\n',1)[1]
header=header.rsplit('#endif\n#endif',1)[0]
header='\n'.join(line for line in header.splitlines() if not line.startswith('#include'))
source='\n'.join(line for line in (ROOT/'user/lib/netdb.c').read_text().splitlines() if not line.startswith('#include'))
source=re.sub(r'\bcalloc\b','checked_calloc',source)
source=re.sub(r'\bfree\b','checked_free',source)
prelude=r'''
#define _DARWIN_C_SOURCE 1
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#define TTF_HOST_BUILD 1
'''+f'#include "{ROOT / "include/syscall_defs.h"}"\n'+r'''
#define CHECK(c) do{if(!(c)){fprintf(stderr,"netdb contract line %d: %s\n",__LINE__,#c);abort();}}while(0)
static _Thread_local int fail_after=-1;
static unsigned live;
static void *checked_calloc(size_t count,size_t size){if(fail_after==0){errno=ENOMEM;return NULL;}if(fail_after>0)--fail_after;void *p=calloc(count,size);if(p)__atomic_add_fetch(&live,1,__ATOMIC_RELAXED);return p;}
static void checked_free(void *p){if(p){CHECK(__atomic_fetch_sub(&live,1,__ATOMIC_RELAXED));free(p);}}
static _Thread_local bool configured=true;
static ssize_t sys_net_snapshot(syscall_net_stats_t *out,size_t capacity){CHECK(capacity==8);memset(out,0,capacity*sizeof(*out));out[0].present=1;out[0].ipv4_addr=configured?0x0a00020f:0;return 1;}
static _Thread_local unsigned queries;
static _Thread_local uint32_t last_server;
static _Thread_local uint16_t last_port;
static int __alix_dns_query4(const char *name,uint32_t server,uint16_t port,syscall_dns_reply_t *reply){
 ++queries;last_server=server;last_port=port;memset(reply,0,sizeof(*reply));reply->version=SYSCALL_DNS_VERSION;reply->size=sizeof(*reply);
 if(!strcmp(name,"missing.test")){reply->status=SYSCALL_DNS_NOT_FOUND;return 0;}
 if(!strcmp(name,"again.test")){reply->status=SYSCALL_DNS_AGAIN;return 0;}
 if(!strcmp(name,"failed.test")){reply->status=SYSCALL_DNS_FAILURE;return 0;}
 if(!strcmp(name,"system.test")){errno=EIO;return-1;}
 CHECK(!strcmp(name,"multi.test"));reply->address_count=2;reply->addresses[0]=0x0a010203;reply->addresses[1]=0x0a010204;strcpy(reply->canonical,"canonical.test");reply->canonical_length=strlen(reply->canonical);return 0;
}
'''
tests=r'''
static void lookup_and_flags(void){
 struct addrinfo hints={.ai_family=AF_INET,.ai_socktype=SOCK_STREAM},*result=(void*)1;
 CHECK(getaddrinfo(NULL,NULL,NULL,&result)==EAI_NONAME&&!result);
 hints.ai_flags=AI_NUMERICHOST;unsigned before=queries;
 CHECK(getaddrinfo("multi.test","80",&hints,&result)==EAI_NONAME&&!result&&queries==before);
 CHECK(getaddrinfo("localhost","80",&hints,&result)==EAI_NONAME&&!result);
 CHECK(!getaddrinfo("10.1.2.3","443",&hints,&result));struct sockaddr_in *address=(void*)result->ai_addr;
 CHECK(ntohl(address->sin_addr.s_addr)==0x0a010203&&ntohs(address->sin_port)==443&&!result->ai_next);freeaddrinfo(result);
 hints.ai_flags=AI_PASSIVE;CHECK(!getaddrinfo(NULL,"https",&hints,&result));address=(void*)result->ai_addr;CHECK(!address->sin_addr.s_addr&&ntohs(address->sin_port)==443);freeaddrinfo(result);
 hints.ai_flags=AI_CANONNAME;CHECK(getaddrinfo(NULL,"80",&hints,&result)==EAI_BADFLAGS&&!result);
 CHECK(!__alix_getaddrinfo_at("multi.test","https",&hints,0x0a000202,1053,&result)&&last_server==0x0a000202&&last_port==1053);
 CHECK(result&&result->ai_next&&!result->ai_next->ai_next&&!strcmp(result->ai_canonname,"canonical.test")&&!result->ai_next->ai_canonname);
 CHECK(ntohl(((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr)==0x0a010203&&ntohl(((struct sockaddr_in*)result->ai_next->ai_addr)->sin_addr.s_addr)==0x0a010204);freeaddrinfo(result);
 CHECK(getaddrinfo("missing.test",NULL,&hints,&result)==EAI_NONAME&&!result);
 CHECK(getaddrinfo("again.test",NULL,&hints,&result)==EAI_AGAIN&&!result);
 CHECK(getaddrinfo("failed.test",NULL,&hints,&result)==EAI_FAIL&&!result);
 CHECK(getaddrinfo("system.test",NULL,&hints,&result)==EAI_SYSTEM&&!result&&errno==EIO);
 hints.ai_family=AF_INET6;CHECK(getaddrinfo("multi.test",NULL,&hints,&result)==EAI_FAMILY);
 hints.ai_family=AF_INET;hints.ai_socktype=SOCK_DGRAM;CHECK(getaddrinfo("multi.test",NULL,&hints,&result)==EAI_SOCKTYPE);
 hints.ai_socktype=SOCK_STREAM;hints.ai_flags=0x40000000;CHECK(getaddrinfo("multi.test",NULL,&hints,&result)==EAI_BADFLAGS);
 hints.ai_flags=AI_ADDRCONFIG;configured=false;before=queries;CHECK(getaddrinfo("multi.test",NULL,&hints,&result)==EAI_NONAME&&queries==before);configured=true;
 hints.ai_flags=AI_NUMERICSERV;CHECK(getaddrinfo("multi.test","https",&hints,&result)==EAI_NONAME);
 CHECK(getaddrinfo("multi.test","9999999999999999999999999",&hints,&result)==EAI_SERVICE);
 CHECK(!live);
}
static void failures_and_packing(void){
 struct addrinfo hints={.ai_family=AF_INET,.ai_flags=AI_CANONNAME},*result=NULL;
 for(int fail=0;fail<3;++fail){fail_after=fail;CHECK(getaddrinfo("multi.test",NULL,&hints,&result)==EAI_MEMORY&&!result&&!live);}fail_after=-1;
 struct hostent entry,*host=NULL;char *buffer=malloc(512);CHECK(buffer);int error;
 memset(buffer,0x5a,512);CHECK(gethostbyname_r("localhost",&entry,buffer+1,4,&host,&error)==ERANGE&&!host&&error==NETDB_INTERNAL&&buffer[1]==0x5a);
 CHECK(!gethostbyname_r("multi.test",&entry,buffer+1,511,&host,&error)&&host==&entry&&!error&&!strcmp(entry.h_name,"canonical.test")&&entry.h_length==4&&entry.h_addrtype==AF_INET);
 CHECK(entry.h_addr_list[0]&&entry.h_addr_list[1]&&!entry.h_addr_list[2]&&!entry.h_aliases[0]);
 uint32_t address;memcpy(&address,entry.h_addr_list[1],4);CHECK(ntohl(address)==0x0a010204);
 CHECK(!gethostbyname_r("missing.test",&entry,buffer,512,&host,&error)&&!host&&error==HOST_NOT_FOUND);
 struct protoent protocol,*p=NULL;CHECK(!getprotobyname_r("tcp",&protocol,buffer+1,511,&p)&&p==&protocol&&p->p_proto==6&&!strcmp(p->p_name,"tcp"));
 struct servent service,*s=NULL;CHECK(!getservbyname_r("https","tcp",&service,buffer+1,511,&s)&&s==&service&&ntohs((uint16_t)s->s_port)==443&&!strcmp(s->s_proto,"tcp"));
 CHECK(getservbyname_r("not-a-service","tcp",&service,buffer,512,&s)==ENOENT&&!s);free(buffer);CHECK(!live);
}
static void name_output(void){
 struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(443)};address.sin_addr.s_addr=htonl(0x0a010203);
 char *buffer=malloc(64);CHECK(buffer);memset(buffer,0x5a,64);
 CHECK(!getnameinfo((struct sockaddr*)&address,sizeof(address),buffer,32,buffer+32,32,NI_NUMERICHOST|NI_NUMERICSERV)&&!strcmp(buffer,"10.1.2.3")&&!strcmp(buffer+32,"443"));
 memset(buffer,0x5a,64);CHECK(getnameinfo((struct sockaddr*)&address,sizeof(address),buffer,3,buffer+32,32,NI_NUMERICHOST)==EAI_OVERFLOW&&buffer[0]==0x5a&&buffer[32]==0x5a);
 CHECK(getnameinfo((struct sockaddr*)&address,sizeof(address),buffer,32,NULL,0,NI_NAMEREQD)==EAI_NONAME);
 address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);CHECK(!getnameinfo((struct sockaddr*)&address,sizeof(address),buffer,32,buffer+32,32,0)&&!strcmp(buffer,"localhost")&&!strcmp(buffer+32,"https"));free(buffer);
}
typedef struct {unsigned index;pthread_t thread;struct hostent *host;char *name;} job_t;
static void *tls_worker(void *argument){job_t *job=argument;job->host=gethostbyname("localhost");CHECK(job->host&&job->host->h_addr_list[0]);job->name=job->host->h_name;CHECK(!strcmp(job->name,"localhost"));CHECK(getprotobynumber(6)->p_proto==6&&ntohs((uint16_t)getservbyport(htons(443),"tcp")->s_port)==443);return NULL;}
int main(void){lookup_and_flags();failures_and_packing();name_output();
 job_t *jobs=calloc(8,sizeof(*jobs));CHECK(jobs);for(unsigned n=0;n<8;++n){jobs[n].index=n;CHECK(!pthread_create(&jobs[n].thread,NULL,tls_worker,&jobs[n]));}
 for(unsigned n=0;n<8;++n)CHECK(!pthread_join(jobs[n].thread,NULL));free(jobs);CHECK(!live);puts("NETDB: PASS lookup=1 flags=1 errors=1 allocation_rollback=1 packing=1 output_bounds=1 tls_threads=8");return 0;
}
'''
# Prefix declarations, implementation and tests together; host libc keeps its
# original names while production field packing and allocation code executes.
code=header+'\n'+source+'\n'+tests
names=('getaddrinfo','freeaddrinfo','gai_strerror','getnameinfo','gethostbyname','gethostbyname2','gethostbyaddr','gethostbyname_r','gethostbyname2_r','gethostbyaddr_r','getprotobyname','getprotobynumber','getservbyname','getservbyport','getprotobyname_r','getprotobynumber_r','getservbyname_r','getservbyport_r','sethostent','endhostent','setprotoent','endprotoent','setservent','endservent','__h_errno_location','h_errno','addrinfo','hostent','protoent','servent')
for name in names:code=re.sub(r'\b'+name+r'\b','native_'+name,code)
previous=os.environ.get('HOST_CC')
try:
 os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
 compile_and_run('netdb',prelude+code)
finally:
 if previous is None:os.environ.pop('HOST_CC',None)
 else:os.environ['HOST_CC']=previous
print('Production netdb lookup, rollback, packing, output bounds and TLS contracts passed')
