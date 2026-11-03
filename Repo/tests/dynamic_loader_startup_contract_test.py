#!/usr/bin/env python3
"""Execute the production executable-GOT fixup path with faulted ELF metadata."""
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

source = (ROOT / "user/lib/dlfcn.c").read_text()
functions = "\n".join(function_definition(source, signature) for signature in (
    "static bool dl_startup_range(", "static void dl_main_startup("))
assembly = '__asm__ volatile("movq %%fs:0,%0\\n\\tmovq %%fs:8,%1" : "=r"(tp), "=r"(block));'
assert functions.count(assembly) == 1
functions = functions.replace(assembly, "tp = model_tp; block = model_block;")
assert functions.count("__builtin_trap();") == 1
functions = functions.replace("__builtin_trap();", "longjmp(failure, 1);")
code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
'''
code += '#include "' + str(ROOT / "user/lib/dynamic_elf.h") + '"\n'
code += r'''
#define CHECK(c) do {if(!(c)){fprintf(stderr,"startup contract %d: %s\n",__LINE__,#c);abort();}}while(0)
static unsigned char *image;
static uintptr_t model_tp = 0x100000, model_block = 0xff000;
static bool dl_startup_done;
static jmp_buf failure;
#define __alix_user_pointer_base image
#define __alix_user_data_start (image + 32768)
#define __alix_user_image_loaded_end (image + 65536)
#define __alix_dynamic_start ((dl_dyn *)(image + 256))
#define __alix_dynamic_end (__alix_dynamic_start + 16)
#define __alix_static_tls_bytes ((char *)64)
'''
code += functions
code += r'''
static dl_dyn *dynamic;
static dl_rela *relocations;
static dl_sym *symbols;
static uint64_t *slots;
static void reset(void) {
    memset(image,0,65536); dl_startup_done=false;
    dynamic=__alix_dynamic_start; symbols=(dl_sym *)(image+4096);
    relocations=(dl_rela *)(image+8192); slots=(uint64_t *)(image+32768);
    dynamic[0]=(dl_dyn){DL_SYMTAB,(uintptr_t)symbols};
    dynamic[1]=(dl_dyn){DL_RELA,(uintptr_t)relocations};
    dynamic[2]=(dl_dyn){DL_RELASZ,4*sizeof(dl_rela)};
    symbols[1]=(dl_sym){.info=0x12,.section=1,.value=(uintptr_t)image+16384,.size=8};
    symbols[2]=(dl_sym){.info=0x16,.section=2,.value=16,.size=8};
    symbols[3]=(dl_sym){.info=0x20}; // undefined weak function
    symbols[4]=(dl_sym){.info=0x10,.section=0xfff1,.value=0}; // defined absolute NULL
    relocations[0]=(dl_rela){(uintptr_t)&slots[0],((uint64_t)1<<32)|DL_GLOB_DAT,0};
    relocations[1]=(dl_rela){(uintptr_t)&slots[1],((uint64_t)2<<32)|DL_TPOFF64,-8};
    relocations[2]=(dl_rela){(uintptr_t)&slots[2],((uint64_t)3<<32)|DL_GLOB_DAT,0};
    relocations[3]=(dl_rela){(uintptr_t)&slots[3],((uint64_t)4<<32)|DL_GLOB_DAT,0};
    for(unsigned i=0;i<4;++i)slots[i]=0xdeadbeef;
}
static bool run(void) {
    if(setjmp(failure))return false;
    dl_main_startup();return true;
}
int main(void) {
    image=calloc(1,65536);CHECK(image);
    reset();CHECK(run()&&dl_startup_done);
    CHECK(slots[0]==symbols[1].value && slots[1]==model_block-model_tp+8 && !slots[2]&&!slots[3]);
    unsigned rejected=0;
    for(unsigned which=0;which<18;++which){
        reset();
        switch(which){
        case 0:relocations[0].offset=(uintptr_t)image+16384;break;
        case 1:relocations[0].offset=(uintptr_t)slots+1;break;
        case 2:relocations[0].info=((uint64_t)UINT32_MAX<<32)|DL_GLOB_DAT;break;
        case 3:relocations[0].addend=1;break;
        case 4:symbols[1].info=0x1a;break; // IFUNC is not an ordinary function
        case 5:symbols[1].section=0;break;
        case 6:symbols[1].value=UINTPTR_MAX;break;
        case 7:symbols[1].size=UINT64_MAX;break;
        case 8:relocations[0].info=((uint64_t)1<<32)|DL_R64;break;
        case 9:dynamic[2].value=sizeof(dl_rela)-1;break;
        case 10:dynamic[1].value=UINTPTR_MAX-8;break;
        case 11:dynamic[3]=(dl_dyn){DL_NEEDED,1};break;
        case 12:relocations[1].addend=INT64_MIN;break;
        case 13:relocations[1].addend=INT64_MAX;break;
        case 14:symbols[2].section=0xfff1;break;
        case 15:symbols[2].value=65;break;
        case 16:symbols[2].size=65;break;
        case 17:symbols[3].value=1;break;
        }
        CHECK(!run()&&!dl_startup_done);++rejected;
    }
    reset();dynamic[2].value=0;CHECK(run()&&dl_startup_done);
    free(image);printf("Executable GOT startup: PASS functions=1 tls=1 weak=1 absolute_null=1 rejected=%u\n",rejected);
}
'''
compile_and_run("dynamic-loader-startup", code)
print("Executable GOT startup contract: PASS TLS/functions/weak/absolute-NULL, 18 rejected metadata cases")
