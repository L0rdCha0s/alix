#!/usr/bin/env python3
"""Check production kernel copies against libc, including overlap and page ends."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    source = (ROOT / 'src/kernel/libc.c').read_text()
    start = source.index('typedef struct __attribute__((packed, may_alias))')
    end = source.index('} libc_copy_word_t;', start) + len('} libc_copy_word_t;')
    program = r'''
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
static void libc_mem_debug(const char *label, void *dst, const void *src, size_t count)
{ (void)label; (void)dst; (void)src; (void)count; }
'''
    program += source[start:end] + '\n'
    program += function_definition(source, 'static inline void libc_copy_forward') + '\n'
    program += function_definition(source, 'void *memcpy(').replace('void *memcpy(', 'static void *alix_memcpy(') + '\n'
    program += function_definition(source, 'void *memmove(').replace('void *memmove(', 'static void *alix_memmove(') + '\n'
    program += r'''
#define CHECK(v) do { if (!(v)) { fprintf(stderr,"copy regression at line %d\n",__LINE__); exit(1); } } while (0)
static void fill(uint8_t *p, size_t n) { for(size_t i=0;i<n;i++)p[i]=(uint8_t)(i*37u+i/7u); }
int main(void)
{
    const size_t cap=8192;
    uint8_t *src=malloc(cap),*got=malloc(cap),*want=malloc(cap);
    CHECK(src&&got&&want);fill(src,cap);
    const size_t sizes[]={0,1,2,3,4,5,7,8,9,15,16,17,23,31,32,33,63,64,65,127,128,129,255,256,257,1024,4096};
    for(size_t i=0;i<sizeof(sizes)/sizeof(*sizes);i++) {
        size_t n=sizes[i];
        for(size_t s=0;s<16;s++)for(size_t d=0;d<16;d++) {
            memset(got,0xa5,cap);memset(want,0xa5,cap);
            CHECK(alix_memcpy(got+64+d,src+64+s,n)==got+64+d);
            memcpy(want+64+d,src+64+s,n);
            CHECK(memcmp(got,want,cap)==0);
        }
        for(int delta=-64;delta<=64;delta++) {
            fill(got,cap);fill(want,cap);
            CHECK(alix_memmove(got+128+delta,got+128,n)==got+128+delta);
            memmove(want+128+delta,want+128,n);
            CHECK(memcmp(got,want,cap)==0);
        }
    }
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    uint8_t *a=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    uint8_t *b=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    CHECK(a!=MAP_FAILED&&b!=MAP_FAILED);fill(a,page);
    CHECK(mprotect(a+page,page,PROT_NONE)==0&&mprotect(b+page,page,PROT_NONE)==0);
    CHECK(mprotect(a,page,PROT_READ)==0);
    for(size_t n=0;n<=257;n++) {
        memset(b,0xa5,page);
        CHECK(alix_memcpy(b+page-n,a+page-n,n)==b+page-n);
        CHECK(memcmp(b+page-n,a+page-n,n)==0);
        CHECK(alix_memmove(b+page-n,a+page-n,n)==b+page-n);
    }
    CHECK(munmap(a,2*page)==0&&munmap(b,2*page)==0);
    free(src);free(got);free(want);
    puts("kernel copy alignment, overlap, and protected-page boundaries passed");
    return 0;
}
'''
    compile_and_run('kernel-memory-copy', program)


if __name__ == '__main__':
    main()
