#!/usr/bin/env python3
"""Check production strncat bounds and exact writes, including a page edge."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def main():
    source = (ROOT / "user/lib/libc.c").read_text()
    implementation = function_definition(source, "char *strncat(").replace("strncat(", "alix_strncat(", 1)
    program = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#define CHECK(value) do { if (!(value)) { fprintf(stderr,"strncat check failed line %d: %s\n",__LINE__,#value); exit(1); } } while(0)
''' + implementation + r'''
int main(void) {
    char *output=malloc(32);CHECK(output);
    memset(output,0x5a,32);memcpy(output,"ab",3);
    CHECK(alix_strncat(output,"xyz",2)==output);
    CHECK(memcmp(output,"abxy",5)==0 && output[5]==0x5a);
    CHECK(alix_strncat(output,"q",SIZE_MAX)==output);
    CHECK(memcmp(output,"abxyq",6)==0 && output[6]==0x5a);
    CHECK(alix_strncat(output,"",16)==output && output[6]==0x5a);
    output[0]=0;
    CHECK(alix_strncat(output,"abc",3)==output && memcmp(output,"abc",4)==0);
    long page=sysconf(_SC_PAGESIZE);CHECK(page>0);
    unsigned char *mapping=mmap(NULL,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    CHECK(mapping!=MAP_FAILED && mprotect(mapping+page,(size_t)page,PROT_NONE)==0);
    memcpy(mapping+page-4,"WXYZ",4);
    memset(output,0x5a,32);memcpy(output,"a",2);
    CHECK(alix_strncat(output,(char*)mapping+page-4,4)==output);
    CHECK(memcmp(output,"aWXYZ",6)==0 && output[6]==0x5a);
    CHECK(alix_strncat(output,(char*)mapping+page,0)==output);
    CHECK(memcmp(output,"aWXYZ",6)==0 && output[6]==0x5a);
    /* An early NUL must stop reads even when n spans the inaccessible page. */
    mapping[page-1]=0;
    output[0]=0;
    CHECK(alix_strncat(output,(char*)mapping+page-1,32)==output && output[0]==0);
    CHECK(munmap(mapping,(size_t)page*2)==0);free(output);
}
'''
    compile_and_run("strncat-contract", program)
    print("strncat bounded append, terminator, no-padding and page-edge contracts passed")


if __name__ == "__main__":
    main()
