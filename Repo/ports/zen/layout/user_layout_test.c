#include "userlib.h"
#include "memory_layout.h"
#include "sys/mman.h"
#include "errno.h"
#include "serial.h"

#define PAGE 4096ULL
#define PAYLOAD_BYTES (32ULL<<20)
#define SPARSE_BYTES (12ULL<<30)
#define SPARSE_BASE ((32ULL<<40)-(6ULL<<30))
#define WORKERS 8u
#define SAMPLES 8u
#define PATTERN 0xA11C4D6000000000ULL
#define CHECK(condition,label) do { if(!(condition)) { \
    serial_printf("USER_LAYOUT_TEST: FAIL %s\n",label);return 1; } } while(0)

extern const volatile unsigned char alix_layout_payload[PAYLOAD_BYTES];
extern unsigned char __alix_user_pointer_base[],__alix_user_pointer_limit[];
extern unsigned char __alix_user_stack_top[],__alix_user_stack_size[],__alix_user_stack_guard_size[];
extern unsigned char __alix_user_heap_base[],__alix_user_heap_size[],__alix_user_vm_start[],__alix_user_vm_end[];
extern unsigned char __alix_user_stub_code_base[],__alix_user_image_end[];
static _Thread_local uint64_t tls_number=0x123456789ABCDEF0ULL;
static _Thread_local unsigned char tls_bytes[64] __attribute__((aligned(128)));

typedef struct layout_shared layout_shared_t;
typedef struct
{
    layout_shared_t *shared;
    alix_thread_t thread;
    unsigned index,failed,cpu_mask;
    uintptr_t tls_address,thread_pointer,stack_address;
    uint64_t reads;
} layout_worker_t;
struct layout_shared
{
    volatile uint64_t *samples[SAMPLES];
    unsigned ready,start,stop;
    layout_worker_t workers[WORKERS];
};

static void layout_worker(void *argument)
{
    layout_worker_t *worker=argument;layout_shared_t *shared=worker->shared;
    __asm__ volatile("mov %%rsp,%0":"=r"(worker->stack_address));
    worker->tls_address=(uintptr_t)&tls_number;
    worker->thread_pointer=sys_thread_get_tls();
    uintptr_t auxiliary=(uintptr_t)__alix_user_vm_end,top=(uintptr_t)__alix_user_stub_code_base;
    if(worker->stack_address<auxiliary || worker->stack_address>=top || worker->tls_address<auxiliary ||
       worker->tls_address>=top || worker->thread_pointer<auxiliary || worker->thread_pointer>=top ||
       *(uintptr_t *)worker->thread_pointer!=worker->thread_pointer || tls_number!=0x123456789ABCDEF0ULL ||
       ((uintptr_t)tls_bytes&127)) worker->failed=1;
    for(unsigned i=0;i<sizeof(tls_bytes);++i) if(tls_bytes[i]) worker->failed=1;
    tls_number=worker->index+1;
    memset(tls_bytes,(int)(worker->index+1),sizeof(tls_bytes));
    __atomic_add_fetch(&shared->ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&shared->start,__ATOMIC_ACQUIRE)) sys_yield();
    unsigned round=0;
    do
    {
        unsigned cpu=(worker->index+round++)%WORKERS;
        if(sys_thread_set_affinity(cpu) || sys_thread_cpu()!=cpu) worker->failed=1;
        worker->cpu_mask|=1u<<cpu;
        if(tls_number!=worker->index+1 || sys_thread_get_tls()!=worker->thread_pointer) worker->failed=1;
        for(unsigned i=0;i<sizeof(tls_bytes);++i) if(tls_bytes[i]!=worker->index+1) worker->failed=1;
        for(unsigned i=0;i<SAMPLES;++i)
        {
            if(*shared->samples[i]!=(PATTERN+i)) worker->failed=1;
            ++worker->reads;
        }
        sys_sleep_ms(1);
    } while(round<WORKERS || !__atomic_load_n(&shared->stop,__ATOMIC_ACQUIRE));
}

int main(void)
{
    CHECK((uintptr_t)__alix_user_pointer_base==USER_DEFAULT_POINTER_BASE &&
          (uintptr_t)__alix_user_pointer_limit==USER_DEFAULT_POINTER_LIMIT &&
          (uintptr_t)__alix_user_stack_top==USER_DEFAULT_POINTER_BASE+USER_DEFAULT_STACK_TOP_OFFSET &&
          (uintptr_t)__alix_user_stack_size==USER_DEFAULT_STACK_SIZE &&
          (uintptr_t)__alix_user_heap_base==USER_DEFAULT_POINTER_BASE+USER_DEFAULT_HEAP_BASE_OFFSET &&
          (uintptr_t)__alix_user_heap_size==USER_DEFAULT_HEAP_SIZE &&
          (uintptr_t)__alix_user_image_end==USER_DEFAULT_IMAGE_END,"C/linker layout identity");
    uintptr_t stack;__asm__ volatile("mov %%rsp,%0":"=r"(stack));
    CHECK(stack<(uintptr_t)__alix_user_stack_top && stack>=(uintptr_t)__alix_user_stack_top-USER_DEFAULT_STACK_SIZE,"8MiB main stack range");
    uintptr_t heap=(uintptr_t)sys_sbrk(0);
    CHECK(heap>=(uintptr_t)__alix_user_heap_base && heap<(uintptr_t)__alix_user_heap_base+USER_DEFAULT_HEAP_SIZE,"16GiB heap reservation");
    CHECK((uintptr_t)alix_layout_payload>=USER_DEFAULT_POINTER_BASE &&
          (uintptr_t)alix_layout_payload+PAYLOAD_BYTES<=USER_DEFAULT_IMAGE_END,"large constant LOAD image");
    for(size_t page=0;page<PAYLOAD_BYTES/PAGE;++page)
    {
        unsigned char expected=(unsigned char)((page*73u)^0xA5u);
        CHECK(alix_layout_payload[page*PAGE]==expected && alix_layout_payload[(page+1)*PAGE-1]==expected,"32MiB file payload bytes");
    }
    syscall_thread_info_t *info=calloc(1,sizeof(*info));CHECK(info,"thread info allocation");
    CHECK(sys_thread_info(0,info)==0 && info->stack_size==USER_DEFAULT_STACK_SIZE &&
          info->guard_size==(uintptr_t)__alix_user_stack_guard_size,"main stack and guard metadata");
    free(info);
    void *hint=mmap((void *)1,PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(hint!=MAP_FAILED && (uintptr_t)hint>=(uintptr_t)__alix_user_vm_start,"out-of-range hint fallback");
    CHECK(munmap(hint,PAGE)==0,"hint cleanup");
    hint=mmap((void *)(SPARSE_BASE+123),PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(hint==(void *)SPARSE_BASE && munmap(hint,PAGE)==0,"unaligned advisory hint");
    CHECK(mmap((void *)(SPARSE_BASE+1),PAGE,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==MAP_FAILED &&
          errno==EINVAL,"fixed mapping alignment remains strict");
    unsigned char *area=mmap((void *)SPARSE_BASE,SPARSE_BYTES,PROT_NONE,
                             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0);
    CHECK(area==(void *)SPARSE_BASE,"12GiB sparse reservation");
    layout_shared_t *shared=calloc(1,sizeof(*shared));CHECK(shared,"heap-owned shared state");
    const size_t offsets[SAMPLES]={0,PAGE,2ULL<<30,(6ULL<<30)-PAGE,6ULL<<30,(8ULL<<30)+PAGE,SPARSE_BYTES-2*PAGE,SPARSE_BYTES-PAGE};
    for(unsigned i=0;i<SAMPLES;++i)
    {
        unsigned char *page=area+offsets[i];
        CHECK(mprotect(page,PAGE,PROT_READ|PROT_WRITE)==0,"single-page sparse commit");
        CHECK(*(uint64_t *)page==0,"new high page is zero");
        shared->samples[i]=(volatile uint64_t *)page;
        *shared->samples[i]=PATTERN+i;
        CHECK(sys_time_info((syscall_time_info_t *)(page+64))==0,"high-address syscall copy");
    }
    CHECK(((uintptr_t)shared->samples[3]>>39)==63 && ((uintptr_t)shared->samples[4]>>39)==64,"cross-PML4 endpoints");
    for(unsigned i=0;i<WORKERS;++i)
    {
        shared->workers[i].shared=shared;shared->workers[i].index=i;
        CHECK(alix_thread_create(&shared->workers[i].thread,"high-layout",layout_worker,&shared->workers[i])==0,"high TLS/thread stack creation");
    }
    while(__atomic_load_n(&shared->ready,__ATOMIC_ACQUIRE)!=WORKERS) sys_yield();
    __atomic_store_n(&shared->start,1,__ATOMIC_RELEASE);
    for(unsigned round=0;round<8;++round)
        for(unsigned i=0;i<SAMPLES;++i)
        {
            CHECK(mprotect((void *)shared->samples[i],PAGE,PROT_READ)==0,"high SMP read protection");
            CHECK(mprotect((void *)shared->samples[i],PAGE,PROT_READ|PROT_WRITE)==0,"high SMP write restoration");
        }
    __atomic_store_n(&shared->stop,1,__ATOMIC_RELEASE);
    for(unsigned i=0;i<WORKERS;++i)
    {
        layout_worker_t *worker=&shared->workers[i];
        CHECK(alix_thread_join(worker->thread,NULL)==0 && !worker->failed && worker->cpu_mask==0xFF && worker->reads>=64,"eight-CPU access and TLS");
        for(unsigned j=0;j<i;++j) CHECK(worker->tls_address!=shared->workers[j].tls_address,"private high TLS blocks");
    }
    const unsigned char code[]={0xB8,42,0,0,0,0xC3};
    unsigned char *executable=(unsigned char *)shared->samples[4];
    memcpy(executable+512,code,sizeof(code));
    CHECK(mprotect(executable,PAGE,PROT_READ|PROT_EXEC)==0 &&
          ((int (*)(void))(uintptr_t)(executable+512))()==42,"generated code in high PML4 entry");
    CHECK(munmap(area,SPARSE_BYTES)==0,"sparse interval release");
    CHECK(sys_time_info((syscall_time_info_t *)(area+64))<0,"released high pages reject copies");
    free(shared);
    serial_printf("USER_LAYOUT_TEST: PASS payload=32MiB sparse=12GiB pages=8 workers=8 cpu_mask=0xFF pml4=63,64 tls_high=1 jit=42\n");
    return 0;
}
