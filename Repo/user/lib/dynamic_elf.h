#ifndef ALIX_DYNAMIC_ELF_H
#define ALIX_DYNAMIC_ELF_H
#include "stdint.h"
typedef struct
{
    unsigned char ident[16];
    uint16_t type, machine;
    uint32_t version;
    uint64_t entry, phoff, shoff;
    uint32_t flags;
    uint16_t ehsize, phentsize, phnum, shentsize, shnum, shstrndx;
} dl_ehdr;
typedef struct
{
    uint32_t type, flags;
    uint64_t offset, vaddr, paddr, filesz, memsz, align;
} dl_phdr;
typedef struct
{
    int64_t tag;
    uint64_t value;
} dl_dyn;
typedef struct
{
    uint32_t name;
    unsigned char info, other;
    uint16_t section;
    uint64_t value, size;
} dl_sym;
typedef struct
{
    uint64_t offset, info;
    int64_t addend;
} dl_rela;
typedef struct { uint16_t version, flags, index, count; uint32_t hash, aux, next; } dl_verdef;
typedef struct { uint32_t name, next; } dl_verdaux;
typedef struct { uint16_t version, count; uint32_t file, aux, next; } dl_verneed;
typedef struct { uint32_t hash; uint16_t flags, index; uint32_t name, next; } dl_vernaux;
enum
{
    DL_LOAD = 1,
    DL_DYNAMIC = 2,
    DL_INTERP = 3,
    DL_TLS = 7,
    DL_RELRO = 0x6474e552
};
enum
{
    DL_X = 1,
    DL_W = 2,
    DL_R = 4
};
enum
{
    DL_NEEDED = 1,
    DL_PLTRELSZ = 2,
    DL_HASH = 4,
    DL_STRTAB = 5,
    DL_SYMTAB = 6,
    DL_RELA = 7,
    DL_RELASZ = 8,
    DL_RELAENT = 9,
    DL_STRSZ = 10,
    DL_SYMENT = 11,
    DL_INIT = 12,
    DL_FINI = 13,
    DL_SONAME = 14,
    DL_RPATH = 15,
    DL_SYMBOLIC = 16,
    DL_REL = 17,
    DL_RELSZ = 18,
    DL_PLTREL = 20,
    DL_TEXTREL = 22,
    DL_JMPREL = 23,
    DL_INIT_ARRAY = 25,
    DL_FINI_ARRAY = 26,
    DL_INIT_ARRAYSZ = 27,
    DL_FINI_ARRAYSZ = 28,
    DL_RUNPATH = 29,
    DL_FLAGS = 30,
    DL_RELRSZ = 35,
    DL_RELR = 36,
    DL_RELRENT = 37,
    DL_GNU_HASH = 0x6ffffef5,
    DL_FLAGS_1 = 0x6ffffffb,
    DL_VERSYM = 0x6ffffff0,
    DL_VERDEF = 0x6ffffffc,
    DL_VERDEFNUM = 0x6ffffffd,
    DL_VERNEED = 0x6ffffffe,
    DL_VERNEEDNUM = 0x6fffffff
};
enum
{
    DL_R64 = 1,
    DL_PC32 = 2,
    DL_GLOB_DAT = 6,
    DL_JUMP_SLOT = 7,
    DL_RELATIVE = 8,
    DL_R32 = 10,
    DL_R32S = 11,
    DL_DTPMOD64 = 16,
    DL_DTPOFF64 = 17,
    DL_TPOFF64 = 18,
    DL_PC64 = 24
};
#endif
