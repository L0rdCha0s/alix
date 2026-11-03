#include "dlfcn.h"
#include "alix_mutex.h"
#include "alix_process.h"
#include "dynamic_elf.h"
#include "alix_image.h"
#include "link.h"
#include "errno.h"
#include "fcntl.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/mman.h"
#include "sys/stat.h"
#include "unistd.h"
#include "usyscall.h"

#define DL_PAGE 4096u
#define DL_MODULE_LIMIT 1024u
#define DL_SYMBOL_LIMIT 2000000u
#define DL_SHARED_PAGE 0x80u
#define DL_FILE_PAGE 0x40u
typedef struct dl_module dl_module;
typedef struct
{
    const char *name, *file;
    uint32_t hash;
    bool definition, weak;
} dl_version_info;
struct dl_module
{
    dl_module *next;
    char *path;
    uintptr_t bias, low, high;
    size_t span, reservation_bytes;
    uintptr_t reservation, relro_address;
    size_t relro_bytes;
    dl_phdr *segments;
    size_t segment_count;
    const dl_phdr *program_headers;
    size_t program_header_count;
    dl_dyn *dynamic;
    size_t dynamic_count;
    dl_sym *symbols;
    const char *strings;
    size_t string_bytes, symbol_count;
    uint32_t *hash;
    uintptr_t versym, verdef, verneed;
    size_t verdef_count, verneed_count, version_capacity;
    const uint16_t *version_symbols;
    dl_version_info *versions;
    dl_module **dependencies, **bindings;
    size_t dependency_count, binding_count;
    unsigned external, tls_users, busy;
    uint64_t id, sequence;
    bool main, global, nodelete, mark, relocated, initializing, initialized, finalized, symbolic, deep,
        retiring;
    uintptr_t init, fini, init_array, fini_array, rela, jmprel, relr;
    size_t init_bytes, fini_bytes, rela_bytes, jmp_bytes, relr_bytes;
    const char *runpath, *rpath, *soname;
    uintptr_t tls_image;
    size_t tls_filesz, tls_memsz, tls_align, tls_skew;
};
typedef struct dl_tls_block
{
    struct dl_tls_block *next;
    uint64_t id;
    size_t bytes;
    void *allocation, *value;
} dl_tls_block;
static alix_mutex_t dl_mutex;
static _Thread_local unsigned dl_depth;
static _Thread_local char dl_message[256];
static _Thread_local bool dl_pending;
static _Thread_local dl_tls_block *dl_thread_blocks;
static _Thread_local dl_tls_block *dl_recent_block;
static dl_module dl_main, *dl_modules;
static uint64_t dl_next_id = 2, dl_sequence;
static bool dl_collecting, dl_exit_registered;
static bool dl_startup_done;
static bool dl_startup_dynamic, dl_startup_mapped;

_Static_assert(sizeof(dl_phdr) == sizeof(Elf64_Phdr), "native ELF program header ABI");
extern char __alix_user_pointer_base[], __alix_user_text_end[], __alix_user_data_start[],
    __alix_user_image_loaded_end[];
extern dl_dyn __alix_dynamic_start[], __alix_dynamic_end[];
extern char __alix_static_tls_bytes[];

/* Resolve fixed-address executable GOT imports and initial-exec TLS before
 * user constructors (and SSP initialization). No allocator or protected
 * function may be called here. FS:0 is TP; FS:8 is the static TLS block. */
static bool dl_startup_range(uintptr_t address, size_t bytes, bool writable)
{
    uintptr_t low = writable ? (uintptr_t)__alix_user_data_start : (uintptr_t)__alix_user_pointer_base;
    uintptr_t high = (uintptr_t)__alix_user_image_loaded_end;
    return address >= low && address <= high && bytes <= high - address;
}
static void dl_main_startup(void)
{
    if (&__alix_dynamic_start[0] == &__alix_dynamic_end[0])
        return;
    uintptr_t symbols = 0, relocations = 0;
    size_t bytes = 0;
    bool valid = true;
    for (dl_dyn *d = __alix_dynamic_start; d < __alix_dynamic_end && d->tag; ++d)
    {
        if (d->tag == DL_SYMTAB)
            symbols = d->value;
        if (d->tag == DL_RELA)
            relocations = d->value;
        if (d->tag == DL_RELASZ)
            bytes = d->value;
        if (d->tag == DL_NEEDED || ((d->tag == DL_JMPREL || d->tag == DL_RELR) && d->value))
            dl_startup_dynamic = true;
        if (d->tag == DL_REL && d->value)
            valid = false;
    }
    if (bytes % sizeof(dl_rela) || (bytes && !dl_startup_range(relocations, bytes, false)))
        valid = false;
    uintptr_t tp, block;
    __asm__ volatile("movq %%fs:0,%0\n\tmovq %%fs:8,%1" : "=r"(tp), "=r"(block));
    for (size_t i = 0; valid && i < bytes / sizeof(dl_rela); ++i)
    {
        dl_rela *r = &((dl_rela *)relocations)[i];
        uint64_t index = r->info >> 32;
        uint32_t type = (uint32_t)r->info;
        if (dl_startup_dynamic && type != DL_TPOFF64 && type != DL_GLOB_DAT)
            continue;
        if ((type != DL_TPOFF64 && type != DL_GLOB_DAT) ||
            index > (UINTPTR_MAX - symbols) / sizeof(dl_sym) ||
            !dl_startup_range(symbols + index * sizeof(dl_sym), sizeof(dl_sym), false) || r->offset % 8 ||
            !dl_startup_range(r->offset, 8, true))
        {
            valid = false;
            break;
        }
        dl_sym *s = (dl_sym *)(symbols + index * sizeof(dl_sym));
        uint64_t value = s->value;
        if (type == DL_GLOB_DAT)
        {
            unsigned symbol_type = s->info & 15;
            if (dl_startup_dynamic && !s->section && (s->info >> 4) != 2)
                continue;
            if (r->addend || symbol_type > 2 ||
                (!s->section && ((s->info >> 4) != 2 || s->value || s->size)) ||
                (s->section && s->section != 0xfff1 && !dl_startup_range(value, s->size, false)))
            {
                valid = false;
                break;
            }
        }
        else
        {
            uint64_t limit = (uintptr_t)__alix_static_tls_bytes;
            if (!s->section || s->section == 0xfff1 || (s->info & 15) != 6 ||
                value > limit || s->size > limit - value ||
                (r->addend >= 0 && (uint64_t)r->addend > limit - value) ||
                (r->addend < 0 && (uint64_t)(-(r->addend + 1)) + 1 > value))
            {
                valid = false;
                break;
            }
            value = block - tp + value + (uint64_t)r->addend;
        }
        *(uint64_t *)r->offset = value;
    }
    if (!valid)
        __builtin_trap();
    dl_startup_done = true;
}
__attribute__((section(".preinit_array.alix_runtime"),
               used)) static void (*const dl_startup_entry)(void) = dl_main_startup;

static void dl_lock(void)
{
    if (!dl_depth)
        alix_mutex_lock(&dl_mutex);
    ++dl_depth;
}
static void dl_unlock(void)
{
    if (!--dl_depth)
        alix_mutex_unlock(&dl_mutex);
}
static bool dl_fail(const char *message)
{
    if (!dl_pending)
    {
        snprintf(dl_message, sizeof(dl_message), "%s", message);
        dl_pending = true;
    }
    return false;
}
static bool dl_add_overflow(uint64_t a, uint64_t b, uint64_t *out) { return __builtin_add_overflow(a, b, out); }
static void *dl_pointer(dl_module *m, uint64_t address, size_t bytes, unsigned flags)
{
    uint64_t end;
    if (dl_add_overflow(address, bytes, &end))
        return NULL;
    for (size_t i = 0; i < m->segment_count; ++i)
    {
        dl_phdr *p = &m->segments[i];
        unsigned f = p->flags;
        if (f & DL_X)
            f |= DL_R;
        if ((f & flags) == flags && address >= p->vaddr && end >= address && end - p->vaddr <= p->memsz)
            return (void *)(m->bias + address);
    }
    return NULL;
}
static const char *dl_string(dl_module *m, uint64_t offset)
{
    return offset < m->string_bytes && memchr(m->strings + offset, 0, m->string_bytes - (size_t)offset)
               ? m->strings + offset
               : NULL;
}
static uint32_t dl_hash_name(const char *name);
#define DL_VERSION_LIMIT 32768u
static dl_version_info *dl_version_index(dl_module *m, unsigned index)
{
    return index < m->version_capacity && m->versions[index].name ? &m->versions[index] : NULL;
}
static bool dl_version_add(dl_module *m, unsigned index, uint32_t hash, const char *name,
                           const char *file, bool definition, bool weak)
{
    if (!index || index >= DL_VERSION_LIMIT || !name || !*name || dl_hash_name(name) != hash)
        return dl_fail("invalid ELF version name, hash or index");
    if (index >= m->version_capacity)
    {
        size_t capacity = m->version_capacity ? m->version_capacity : 4;
        while (capacity <= index) capacity *= 2;
        dl_version_info *next = realloc(m->versions, capacity * sizeof(*next));
        if (!next) return dl_fail("out of memory parsing ELF versions");
        memset(next + m->version_capacity, 0, (capacity - m->version_capacity) * sizeof(*next));
        m->versions = next; m->version_capacity = capacity;
    }
    if (m->versions[index].name) return dl_fail("duplicate ELF version index");
    m->versions[index] = (dl_version_info){.name=name,.file=file,.hash=hash,.definition=definition,.weak=weak};
    return true;
}
static bool dl_version_file_needed(dl_module *m, const char *name)
{
    for (size_t i=0;i<m->dynamic_count && m->dynamic[i].tag;++i)
        if (m->dynamic[i].tag==DL_NEEDED)
        {
            const char *needed=dl_string(m,m->dynamic[i].value);
            if (needed && !strcmp(needed,name)) return true;
        }
    return false;
}
static bool dl_versions_parse(dl_module *m)
{
    if ((!m->verdef != !m->verdef_count) || (!m->verneed != !m->verneed_count) ||
        m->verdef_count>=DL_VERSION_LIMIT || m->verneed_count>=DL_VERSION_LIMIT ||
        (m->versym%2) || (m->verdef%4) || (m->verneed%4) ||
        ((m->verdef_count || m->verneed_count) && !m->versym))
        return dl_fail("invalid ELF version table metadata");
    uint64_t address=m->verdef;
    size_t auxiliaries=0;
    for(size_t i=0;i<m->verdef_count;++i)
    {
        const dl_verdef *d=dl_pointer(m,address,sizeof(*d),DL_R);
        if(!d || d->version!=1 || (d->flags&~7u) || !d->count || d->count>DL_VERSION_LIMIT-auxiliaries ||
            d->aux<sizeof(*d) || d->aux%4 || !d->index || d->index>=DL_VERSION_LIMIT ||
            ((d->flags&1)!=0)!=(d->index==1)) return dl_fail("invalid ELF version definition");
        auxiliaries+=d->count;
        uint64_t aux,end;
        if(dl_add_overflow(address,d->aux,&aux))return dl_fail("ELF version definition overflow");
        for(unsigned j=0;j<d->count;++j)
        {
            const dl_verdaux *a=dl_pointer(m,aux,sizeof(*a),DL_R);
            const char *name=a?dl_string(m,a->name):NULL;
            if(!a || !name || !*name || dl_add_overflow(aux,sizeof(*a),&end))return dl_fail("invalid ELF version definition name");
            if(!j && !dl_version_add(m,d->index,d->hash,name,NULL,true,(d->flags&2)!=0))return false;
            if(j+1<d->count)
            {
                if(a->next<sizeof(*a) || a->next%4 || dl_add_overflow(aux,a->next,&aux))return dl_fail("invalid ELF version definition auxiliary chain");
            }
            else if(a->next)return dl_fail("unterminated ELF version definition auxiliary chain");
        }
        if(i+1<m->verdef_count)
        {
            if(d->next<end-address || d->next%4 || dl_add_overflow(address,d->next,&address))return dl_fail("invalid ELF version definition chain");
        }
        else if(d->next)return dl_fail("unterminated ELF version definition chain");
    }
    address=m->verneed;
    for(size_t i=0;i<m->verneed_count;++i)
    {
        const dl_verneed *n=dl_pointer(m,address,sizeof(*n),DL_R);
        const char *file=n?dl_string(m,n->file):NULL;
        if(!n || n->version!=1 || !n->count || n->count>DL_VERSION_LIMIT-auxiliaries ||
            n->aux<sizeof(*n) || n->aux%4 || !file || !*file || !dl_version_file_needed(m,file))
            return dl_fail("invalid ELF version requirement");
        auxiliaries+=n->count;
        uint64_t aux,end;
        if(dl_add_overflow(address,n->aux,&aux))return dl_fail("ELF version requirement overflow");
        for(unsigned j=0;j<n->count;++j)
        {
            const dl_vernaux *a=dl_pointer(m,aux,sizeof(*a),DL_R);
            if(!a || (a->flags&~2u) || (a->index&0x7fffu)<2 ||
                !dl_version_add(m,a->index&0x7fffu,a->hash,dl_string(m,a->name),file,false,(a->flags&2)!=0) ||
                dl_add_overflow(aux,sizeof(*a),&end))return dl_fail("invalid ELF version requirement auxiliary");
            if(j+1<n->count)
            {
                if(a->next<sizeof(*a) || a->next%4 || dl_add_overflow(aux,a->next,&aux))return dl_fail("invalid ELF version requirement auxiliary chain");
            }
            else if(a->next)return dl_fail("unterminated ELF version requirement auxiliary chain");
        }
        if(i+1<m->verneed_count)
        {
            if(n->next<end-address || n->next%4 || dl_add_overflow(address,n->next,&address))return dl_fail("invalid ELF version requirement chain");
        }
        else if(n->next)return dl_fail("unterminated ELF version requirement chain");
    }
    if(m->versym)
    {
        m->version_symbols=dl_pointer(m,m->versym,m->symbol_count*sizeof(uint16_t),DL_R);
        if(!m->version_symbols)return dl_fail("invalid ELF symbol version array");
        for(size_t i=0;i<m->symbol_count;++i)
        {
            unsigned index=m->version_symbols[i]&0x7fffu;
            if(index>1)
            {
                dl_version_info *v=dl_version_index(m,index);
                if(!v || v->definition!=(m->symbols[i].section!=0))return dl_fail("ELF symbol references an unknown or incompatible version");
            }
            else if(m->version_symbols[i]&0x8000u)return dl_fail("hidden reserved ELF symbol version");
        }
    }
    return true;
}
static bool dl_versions_requirements(dl_module *m)
{
    for(size_t v=2;v<m->version_capacity;++v)
    {
        dl_version_info *requirement=&m->versions[v];
        if(!requirement->name || requirement->definition)continue;
        size_t dependency=0;dl_module *provider=NULL;
        for(size_t i=0;i<m->dynamic_count && m->dynamic[i].tag;++i)
            if(m->dynamic[i].tag==DL_NEEDED)
            {
                const char *file=dl_string(m,m->dynamic[i].value);
                if(file && !strcmp(file,requirement->file)){provider=m->dependencies[dependency];break;}
                ++dependency;
            }
        bool found=false;
        if(provider)for(size_t i=2;i<provider->version_capacity;++i)
        {
            dl_version_info *definition=&provider->versions[i];
            if(definition->name && definition->definition && definition->hash==requirement->hash &&
                !strcmp(definition->name,requirement->name)){found=true;break;}
        }
        if(!found && !requirement->weak)
        {
            snprintf(dl_message,sizeof(dl_message),"ELF version %.90s is not provided by %.100s",requirement->name,requirement->file);
            dl_pending=true;return false;
        }
    }
    return true;
}
static bool dl_meta(dl_module *m)
{
    if ((uintptr_t)m->dynamic % _Alignof(dl_dyn))
        return dl_fail("unaligned ELF dynamic table");
    uintptr_t str = 0, sym = 0, hash = 0, gnu = 0;
    size_t syment = 0, relaent = sizeof(dl_rela), relrent = 8;
    uint64_t run = UINT64_MAX, rpath = UINT64_MAX, soname = UINT64_MAX;
    bool terminated = false;
    unsigned version_tags = 0;
    for (size_t i = 0; i < m->dynamic_count; ++i)
    {
        dl_dyn d = m->dynamic[i];
        if (!d.tag)
        {
            terminated = true;
            break;
        }
        switch (d.tag)
        {
        case DL_STRTAB:
            str = d.value;
            break;
        case DL_STRSZ:
            m->string_bytes = d.value;
            break;
        case DL_SYMTAB:
            sym = d.value;
            break;
        case DL_SYMENT:
            syment = d.value;
            break;
        case DL_HASH:
            hash = d.value;
            break;
        case DL_GNU_HASH:
            gnu = d.value;
            break;
        case DL_VERSYM: case DL_VERDEF: case DL_VERDEFNUM: case DL_VERNEED: case DL_VERNEEDNUM:
        {
            unsigned bit = d.tag==DL_VERSYM?1:d.tag==DL_VERDEF?2:d.tag==DL_VERDEFNUM?4:d.tag==DL_VERNEED?8:16;
            if(version_tags&bit)return dl_fail("duplicate ELF version dynamic tag");
            version_tags|=bit;
            if(d.tag==DL_VERSYM)m->versym=d.value;
            else if(d.tag==DL_VERDEF)m->verdef=d.value;
            else if(d.tag==DL_VERDEFNUM)m->verdef_count=d.value;
            else if(d.tag==DL_VERNEED)m->verneed=d.value;
            else m->verneed_count=d.value;
            break;
        }
        case DL_NEEDED:
            ++m->dependency_count;
            break;
        case DL_SONAME:
            if (soname != UINT64_MAX)
                return dl_fail("duplicate ELF SONAME");
            soname = d.value;
            break;
        case DL_RUNPATH:
            run = d.value;
            break;
        case DL_RPATH:
            rpath = d.value;
            break;
        case DL_RELA:
            m->rela = d.value;
            break;
        case DL_RELASZ:
            m->rela_bytes = d.value;
            break;
        case DL_RELAENT:
            relaent = d.value;
            break;
        case DL_JMPREL:
            m->jmprel = d.value;
            break;
        case DL_PLTRELSZ:
            m->jmp_bytes = d.value;
            break;
        case DL_PLTREL:
            if (d.value != DL_RELA)
                return dl_fail("unsupported ELF PLT relocation format");
            break;
        case DL_RELR:
            m->relr = d.value;
            break;
        case DL_RELRSZ:
            m->relr_bytes = d.value;
            break;
        case DL_RELRENT:
            relrent = d.value;
            break;
        case DL_REL:
        case DL_RELSZ:
            if (d.value)
                return dl_fail("unsupported ELF REL relocations");
            break;
        case DL_TEXTREL:
            return dl_fail("ELF text relocations are not supported");
        case DL_FLAGS:
            if (d.value & 4)
                return dl_fail("ELF text relocations are not supported");
            m->symbolic |= (d.value & 2) != 0;
            break;
        case DL_SYMBOLIC:
            m->symbolic = true;
            break;
        case DL_FLAGS_1:
            m->nodelete |= (d.value & 8) != 0;
            break;
        case DL_INIT:
            m->init = d.value;
            break;
        case DL_FINI:
            m->fini = d.value;
            break;
        case DL_INIT_ARRAY:
            m->init_array = d.value;
            break;
        case DL_INIT_ARRAYSZ:
            m->init_bytes = d.value;
            break;
        case DL_FINI_ARRAY:
            m->fini_array = d.value;
            break;
        case DL_FINI_ARRAYSZ:
            m->fini_bytes = d.value;
            break;
        default:
            break;
        }
    }
    if (!terminated || !str || !sym || syment != sizeof(dl_sym) || !m->string_bytes ||
        m->dependency_count > DL_MODULE_LIMIT || relaent != sizeof(dl_rela) || relrent != 8 ||
        m->rela_bytes % sizeof(dl_rela) || m->jmp_bytes % sizeof(dl_rela) || m->relr_bytes % 8 ||
        m->init_bytes % 8 || m->fini_bytes % 8)
        return dl_fail("invalid ELF dynamic metadata");
    if (sym % _Alignof(dl_sym) || (hash && hash % 4) || (gnu && gnu % 4) || m->rela % _Alignof(dl_rela) ||
        m->jmprel % _Alignof(dl_rela) || m->relr % 8 || m->init_array % 8 || m->fini_array % 8)
        return dl_fail("unaligned ELF dynamic metadata");
    m->strings = dl_pointer(m, str, m->string_bytes, DL_R);
    if (!m->strings || m->strings[0])
        return dl_fail("invalid ELF string table");
    if (hash)
    {
        uint32_t *h = dl_pointer(m, hash, 8, DL_R);
        if (!h || !h[0] || h[0] > DL_SYMBOL_LIMIT || !h[1] || h[1] > DL_SYMBOL_LIMIT || (uint64_t)h[0] + h[1] + 2 > SIZE_MAX / 4 ||
            !dl_pointer(m, hash, ((size_t)h[0] + h[1] + 2) * 4, DL_R))
            return dl_fail("invalid ELF hash table");
        m->hash = h;
        m->symbol_count = h[1];
    }
    else if (gnu)
    {
        uint32_t *h = dl_pointer(m, gnu, 16, DL_R);
        if (!h || !h[0] || h[0] > DL_SYMBOL_LIMIT || !h[2] || h[2] > DL_SYMBOL_LIMIT || h[1] > DL_SYMBOL_LIMIT)
            return dl_fail("invalid ELF GNU hash");
        uint64_t bucket_address;
        if (dl_add_overflow(gnu, 16 + (uint64_t)h[2] * 8, &bucket_address))
            return dl_fail("ELF GNU hash overflow");
        uint32_t *buckets = dl_pointer(m, bucket_address, (size_t)h[0] * 4, DL_R);
        if (!buckets)
            return dl_fail("invalid ELF GNU buckets");
        uint32_t maximum = 0;
        for (uint32_t i = 0; i < h[0]; ++i)
            if (buckets[i] > maximum)
                maximum = buckets[i];
        m->symbol_count = h[1];
        if (maximum)
        {
            if (maximum < h[1] || maximum >= DL_SYMBOL_LIMIT)
                return dl_fail("invalid ELF GNU symbol index");
            uint64_t chains = bucket_address + (uint64_t)h[0] * 4;
            for (uint32_t index = maximum;; ++index)
            {
                if (index >= DL_SYMBOL_LIMIT)
                    return dl_fail("unterminated ELF GNU hash");
                uint32_t *chain = dl_pointer(m, chains + (uint64_t)(index - h[1]) * 4, 4, DL_R);
                if (!chain)
                    return dl_fail("invalid ELF GNU chain");
                if (*chain & 1)
                {
                    m->symbol_count = (size_t)index + 1;
                    break;
                }
            }
        }
    }
    else
        return dl_fail("ELF image has no dynamic symbol hash");
    if (!m->symbol_count || m->symbol_count > SIZE_MAX / sizeof(dl_sym) ||
        !(m->symbols = dl_pointer(m, sym, m->symbol_count * sizeof(dl_sym), DL_R)))
        return dl_fail("invalid ELF symbol table");
    if (!dl_versions_parse(m)) return false;
    if (run != UINT64_MAX && !(m->runpath = dl_string(m, run)))
        return dl_fail("invalid ELF RUNPATH");
    if (rpath != UINT64_MAX && !(m->rpath = dl_string(m, rpath)))
        return dl_fail("invalid ELF RPATH");
    if (soname != UINT64_MAX && (!(m->soname = dl_string(m, soname)) || !*m->soname))
        return dl_fail("invalid ELF SONAME");
    if ((m->rela_bytes && !dl_pointer(m, m->rela, m->rela_bytes, DL_R)) ||
        (m->jmp_bytes && !dl_pointer(m, m->jmprel, m->jmp_bytes, DL_R)) ||
        (m->relr_bytes && !dl_pointer(m, m->relr, m->relr_bytes, DL_R)) ||
        (m->init_bytes && !dl_pointer(m, m->init_array, m->init_bytes, DL_R)) ||
        (m->fini_bytes && !dl_pointer(m, m->fini_array, m->fini_bytes, DL_R)))
        return dl_fail("invalid ELF relocation or initialization table");
    return true;
}
static bool dl_main_initialize(void)
{
    if (dl_modules)
        return true;
    dl_main.main = dl_main.global = dl_main.nodelete = dl_main.initialized = dl_main.relocated = true;
    dl_main.relocated = !dl_startup_dynamic;
    dl_main.id = 1;
    dl_main.low = (uintptr_t)__alix_user_pointer_base;
    dl_main.high = (uintptr_t)__alix_user_image_loaded_end;
    dl_main.span = dl_main.high - dl_main.low;
    dl_main.tls_memsz = (uintptr_t)__alix_static_tls_bytes;
    const syscall_elf_info_t *image = __alix_main_image();
    if (!image) return dl_fail("cannot obtain running ELF program headers");
    dl_main.program_headers = (const dl_phdr *)(image + 1);
    dl_main.program_header_count = image->phnum;
    dl_main.segments = calloc(image->phnum, sizeof(dl_phdr));
    if (!dl_main.segments)
        return dl_fail("out of memory initializing loader");
    dl_main.segment_count = 0;
    for (size_t i = 0; i < dl_main.program_header_count; ++i)
        if (dl_main.program_headers[i].type == DL_LOAD && dl_main.program_headers[i].memsz)
            dl_main.segments[dl_main.segment_count++] = dl_main.program_headers[i];
    char *path = malloc(4096);
    if (!path)
    {
        free(dl_main.segments);
        dl_main.segments = NULL;
        return dl_fail("out of memory initializing loader path");
    }
    if (alix_get_executable_path(path, 4096) < 0)
        strcpy(path, "<main>");
    dl_main.path = path;
    dl_main.dynamic = __alix_dynamic_start;
    dl_main.dynamic_count = (size_t)(__alix_dynamic_end - __alix_dynamic_start);
    if (dl_main.dynamic_count && !dl_meta(&dl_main))
    {
        free(path);
        free(dl_main.segments);
        free(dl_main.versions);
        memset(&dl_main, 0, sizeof(dl_main));
        return false;
    }
    if ((dl_main.rela_bytes && !dl_startup_done) ||
        (!dl_startup_dynamic && (dl_main.jmp_bytes || dl_main.relr_bytes || dl_main.dependency_count)))
    {
        free(path);
        free(dl_main.segments);
        free(dl_main.versions);
        memset(&dl_main, 0, sizeof(dl_main));
        return dl_fail("main executable requires a startup dynamic linker");
    }
    dl_modules = &dl_main;
    return true;
}
static uint32_t dl_hash_name(const char *name)
{
    uint32_t h = 0;
    for (unsigned char c; (c = (unsigned char)*name++);)
    {
        h = (h << 4) + c;
        uint32_t high = h & 0xf0000000u;
        if (high)
            h ^= high >> 24;
        h &= ~high;
    }
    return h;
}
static bool dl_version_matches(dl_module *m, size_t index, const dl_version_info *requested)
{
    unsigned value=m->version_symbols?m->version_symbols[index]:1;
    unsigned number=value&0x7fffu;
    if(!number)return false;
    if(!requested)return !(value&0x8000u);
    dl_version_info *version=number>1?dl_version_index(m,number):NULL;
    return version && version->definition && version->hash==requested->hash && !strcmp(version->name,requested->name);
}
static dl_sym *dl_own_symbol_version(dl_module *m, const char *name, const dl_version_info *version)
{
    if (m->retiring)
        return NULL;
    if (!m->symbols)
        return NULL;
    uint32_t index = m->hash ? m->hash[2 + dl_hash_name(name) % m->hash[0]] : 1;
    for (size_t steps = 0; index && index < m->symbol_count && steps < m->symbol_count; ++steps)
    {
        dl_sym *s = &m->symbols[index];
        const char *symbol = dl_string(m, s->name);
        unsigned binding = s->info >> 4, visibility = s->other & 3;
        if (s->section && (binding == 1 || binding == 2 || binding == 10) && visibility != 1 &&
            visibility != 2 && symbol && !strcmp(symbol, name) && dl_version_matches(m,index,version))
            return s;
        index = m->hash ? m->hash[2 + m->hash[0] + index] : index + 1;
    }
    return NULL;
}

static dl_sym *dl_group_symbol_version(dl_module *root, const char *name, const dl_version_info *version, dl_module **owner)
{
    /* Bounded breadth-first scope; dependency cycles visit each module once. */
    dl_module **queue = malloc(DL_MODULE_LIMIT * sizeof(*queue));
    if (!queue)
    {
        dl_fail("out of memory resolving symbols");
        return NULL;
    }
    size_t head = 0, tail = 1;
    queue[0] = root;
    dl_sym *found = NULL;
    while (head < tail)
    {
        dl_module *m = queue[head++];
        if ((found = dl_own_symbol_version(m, name, version)))
        {
            *owner = m;
            break;
        }
        for (size_t i = 0; i < m->dependency_count; ++i)
        {
            dl_module *dep = m->dependencies[i];
            if (!dep)
                continue;
            bool seen = false;
            for (size_t j = 0; j < tail; ++j)
                if (queue[j] == dep)
                    seen = true;
            if (!seen)
            {
                if (tail == DL_MODULE_LIMIT)
                {
                    dl_fail("too many ELF dependencies");
                    goto done;
                }
                queue[tail++] = dep;
            }
        }
    }
done:
    free(queue);
    return found;
}

static dl_sym *dl_resolve_version(dl_module *scope, const char *name, const dl_version_info *version, dl_module **owner)
{
    dl_sym *symbol = NULL;
    if (scope && (scope->deep || scope->symbolic) && (symbol = dl_group_symbol_version(scope, name, version, owner)))
        return symbol;
    for (dl_module *m = dl_modules; m; m = m->next)
        if (m->global && (symbol = dl_own_symbol_version(m, name, version)))
        {
            *owner = m;
            return symbol;
        }
    return scope ? dl_group_symbol_version(scope, name, version, owner) : NULL;
}

static dl_module *dl_by_id(uint64_t id)
{
    for (dl_module *m = dl_modules; m; m = m->next)
        if (m->id == id && !m->retiring)
            return m;
    return NULL;
}
static dl_module *dl_by_address(uintptr_t address)
{
    for (dl_module *m = dl_modules; m; m = m->next)
        for (size_t i = 0; !m->retiring && i < m->segment_count; ++i)
        {
            dl_phdr *p = &m->segments[i];
            uintptr_t start = m->bias + p->vaddr;
            if (address >= start && address - start < p->memsz)
                return m;
        }
    return NULL;
}
static void dl_collect(void);
static void *dl_tls_address(dl_module *m, uint64_t offset)
{
    if (offset >= m->tls_memsz)
    {
        dl_fail("ELF TLS offset is outside its module");
        return NULL;
    }
    if (m->main)
    {
        uintptr_t base;
        __asm__ volatile("movq %%fs:8,%0" : "=r"(base));
        return (void *)(base + offset);
    }
    if (offset >= m->tls_memsz)
    {
        dl_fail("ELF TLS offset is outside its module");
        return NULL;
    }
    for (dl_tls_block *b = dl_thread_blocks; b; b = b->next)
        if (b->id == m->id)
            return (char *)b->value + offset;
    size_t alignment = m->tls_align ? m->tls_align : 1;
    if (alignment > SIZE_MAX / 2 || m->tls_memsz > SIZE_MAX - 2 * alignment || m->tls_users == UINT32_MAX)
    {
        dl_fail("ELF TLS allocation overflow");
        return NULL;
    }
    dl_tls_block *b = calloc(1, sizeof(*b));
    void *allocation = b ? calloc(1, m->tls_memsz + 2 * alignment) : NULL;
    if (!allocation)
    {
        free(b);
        dl_fail("out of memory allocating ELF TLS");
        return NULL;
    }
    uintptr_t value = ((uintptr_t)allocation + alignment - 1) & ~(uintptr_t)(alignment - 1);
    value += m->tls_skew;
    if (m->tls_filesz)
        memcpy((void *)value, (void *)m->tls_image, m->tls_filesz);
    b->id = m->id;
    b->bytes = m->tls_memsz;
    b->allocation = allocation;
    b->value = (void *)value;
    b->next = dl_thread_blocks;
    dl_thread_blocks = b;
    ++m->tls_users;
    return (char *)b->value + offset;
}
void *__tls_get_addr(const uint64_t *index)
{
    /* Each block pins its module until this thread's cleanup. Repeated TLS
     * access needs no process-wide loader lock or module-list traversal. */
    dl_tls_block *cached = dl_recent_block;
    if (cached && cached->id == index[0])
    {
        if (index[1] >= cached->bytes) abort();
        return (char *)cached->value + index[1];
    }
    for (dl_tls_block *block = dl_thread_blocks; block; block = block->next)
    {
        if (block->id != index[0]) continue;
        if (index[1] >= block->bytes) abort();
        dl_recent_block = block;
        return (char *)block->value + index[1];
    }
    dl_lock();
    dl_module *m = dl_by_id(index[0]);
    void *result = m ? dl_tls_address(m, index[1]) : NULL;
    dl_unlock();
    if (!result)
        abort();
    /* dl_tls_address inserts newly allocated dynamic blocks at the head. */
    if (dl_thread_blocks && dl_thread_blocks->id == index[0]) dl_recent_block = dl_thread_blocks;
    return result;
}
void *__alix_dl_pin(const void *address)
{
    dl_lock();
    dl_module *m = dl_by_address((uintptr_t)address);
    if (m && !m->main)
    {
        if (m->tls_users == UINT32_MAX)
            abort();
        ++m->tls_users;
    }
    else
        m = NULL;
    dl_unlock();
    return m;
}
void __alix_dl_unpin(void *owner)
{
    if (!owner)
        return;
    dl_lock();
    dl_module *m = owner;
    if (!m->tls_users)
        abort();
    --m->tls_users;
    dl_collect();
    dl_unlock();
}
void __alix_dl_thread_cleanup(void)
{
    dl_lock();
    dl_recent_block = NULL;
    while (dl_thread_blocks)
    {
        dl_tls_block *block = dl_thread_blocks;
        dl_module *m = dl_by_id(block->id);
        if (!m || !m->tls_users)
            abort();
        --m->tls_users;
        dl_tls_block **cursor = &dl_thread_blocks;
        while (*cursor != block)
            cursor = &(*cursor)->next;
        *cursor = block->next;
        free(block->allocation);
        free(block);
    }
    dl_unlock();
}
static bool dl_symbol_address(dl_module *m, dl_sym *s, uintptr_t *out)
{
    if ((s->info & 15) == 10)
        return dl_fail("GNU indirect functions are not supported");
    if ((s->info & 15) == 6)
    {
        if (s->value >= m->tls_memsz || s->size > m->tls_memsz - s->value)
            return dl_fail("invalid ELF TLS symbol");
        *out = (uintptr_t)dl_tls_address(m, s->value);
        return *out != 0;
    }
    *out = s->section == 0xfff1 ? s->value : m->bias + s->value;
    if (s->section != 0xfff1 && !dl_pointer(m, s->value, s->size, 0))
        return dl_fail("ELF symbol is outside a load segment");
    return true;
}
static bool dl_binding(dl_module *m, dl_module *owner)
{
    if (owner == m || owner->main)
        return true;
    for (size_t i = 0; i < m->binding_count; ++i)
        if (m->bindings[i] == owner)
            return true;
    dl_module **next = realloc(m->bindings, (m->binding_count + 1) * sizeof(*next));
    if (!next)
        return dl_fail("out of memory retaining symbol provider");
    m->bindings = next;
    m->bindings[m->binding_count++] = owner;
    return true;
}
static bool dl_relocate_table(dl_module *m, dl_module *scope, uintptr_t table, size_t bytes)
{
    dl_rela *entries = bytes ? dl_pointer(m, table, bytes, DL_R) : NULL;
    for (size_t i = 0; i < bytes / sizeof(*entries); ++i)
    {
        dl_rela r = entries[i];
        uint32_t type = (uint32_t)r.info;
        uint64_t index = r.info >> 32;
        if (!type)
            continue;
        size_t width = (type == DL_PC32 || type == DL_R32 || type == DL_R32S) ? 4 : 8;
        void *target = dl_pointer(m, r.offset, width, DL_W);
        if (!target)
            return dl_fail("ELF relocation target is not writable data");
        dl_module *owner = m;
        dl_sym *symbol = NULL;
        uintptr_t value = 0;
        if (index)
        {
            if (index >= m->symbol_count)
                return dl_fail("ELF relocation symbol index overflow");
            symbol = &m->symbols[index];
            unsigned binding = symbol->info >> 4;
            if (binding == 0 || ((symbol->other & 3) == 3 && symbol->section) ||
                (symbol->section && m->version_symbols && !(m->version_symbols[index]&0x7fffu)))
            {
                if ((symbol->info & 15) != 6 && !dl_symbol_address(m, symbol, &value))
                    return false;
            }
            else
            {
                const char *name = dl_string(m, symbol->name);
                if (!name)
                    return dl_fail("invalid ELF relocation symbol name");
                unsigned version_index=m->version_symbols?(m->version_symbols[index]&0x7fffu):1;
                const dl_version_info *version=version_index>1?dl_version_index(m,version_index):NULL;
                dl_sym *resolved = m->symbolic ? dl_own_symbol_version(m, name, version) : NULL;
                if (resolved)
                    owner = m;
                else
                    resolved = dl_resolve_version(scope, name, version, &owner);
                if (!resolved)
                {
                    if (dl_pending)
                        return false;
                    if (binding != 2)
                    {
                        snprintf(dl_message, sizeof(dl_message), "unresolved ELF symbol: %.210s", name);
                        dl_pending = true;
                        return false;
                    }
                    owner = NULL;
                }
                else
                {
                    symbol = resolved;
                    if ((symbol->info & 15) != 6 && !dl_symbol_address(owner, symbol, &value))
                        return false;
                    if (!dl_binding(m, owner))
                        return false;
                }
            }
        }
        uint64_t result = value + (uint64_t)r.addend;
        switch (type)
        {
        case DL_RELATIVE:
            if (index)
                return dl_fail("invalid relative ELF relocation");
            result = m->bias + (uint64_t)r.addend;
            break;
        case DL_R64:
            break;
        case DL_GLOB_DAT:
        case DL_JUMP_SLOT:
            result = value;
            break;
        case DL_PC64:
            result -= (uintptr_t)target;
            break;
        case DL_PC32:
        {
            int64_t delta = (int64_t)(result - (uintptr_t)target);
            if (delta < INT32_MIN || delta > INT32_MAX)
                return dl_fail("ELF PC32 relocation overflow");
            result = (uint32_t)delta;
            break;
        }
        case DL_R32:
            if (result > UINT32_MAX)
                return dl_fail("ELF 32-bit relocation overflow");
            break;
        case DL_R32S:
            if ((int64_t)result < INT32_MIN || (int64_t)result > INT32_MAX)
                return dl_fail("ELF signed relocation overflow");
            break;
        case DL_DTPMOD64:
            result = owner ? owner->id : 0;
            break;
        case DL_DTPOFF64:
            result = (symbol ? symbol->value : 0) + (uint64_t)r.addend;
            break;
        case DL_TPOFF64:
        {
            if (!owner || !owner->main || !symbol || (symbol->info & 15) != 6 ||
                !symbol->section || symbol->section == 0xfff1 ||
                symbol->value > owner->tls_memsz || symbol->size > owner->tls_memsz - symbol->value ||
                (r.addend >= 0 && (uint64_t)r.addend > owner->tls_memsz - symbol->value) ||
                (r.addend < 0 && (uint64_t)(-(r.addend + 1)) + 1 > symbol->value))
                return dl_fail("initial-exec DSO TLS requires static TLS allocation");
            uintptr_t tp, block;
            __asm__ volatile("movq %%fs:0,%0\n\tmovq %%fs:8,%1" : "=r"(tp), "=r"(block));
            result = block - tp + symbol->value + (uint64_t)r.addend;
            break;
        }
        default:
            return dl_fail("unsupported x86-64 ELF relocation");
        }
        if (width == 8)
            memcpy(target, &result, 8);
        else
        {
            uint32_t word = (uint32_t)result;
            memcpy(target, &word, 4);
        }
    }
    return true;
}
static bool dl_relocate_packed(dl_module *m)
{
    uint64_t *entries = m->relr_bytes ? dl_pointer(m, m->relr, m->relr_bytes, DL_R) : NULL;
    uint64_t where = 0;
    for (size_t i = 0; i < m->relr_bytes / 8; ++i)
    {
        uint64_t entry = entries[i];
        if (!(entry & 1))
        {
            where = entry;
            uint64_t *p = dl_pointer(m, where, 8, DL_W);
            if (!p)
                return dl_fail("invalid ELF RELR target");
            uint64_t value;
            memcpy(&value, p, 8);
            value += m->bias;
            memcpy(p, &value, 8);
            if (dl_add_overflow(where, 8, &where))
                return dl_fail("ELF RELR overflow");
        }
        else
        {
            if (!where)
                return dl_fail("invalid ELF RELR bitmap");
            for (unsigned bit = 1; bit < 64; ++bit)
                if (entry & (UINT64_C(1) << bit))
                {
                    uint64_t address;
                    if (dl_add_overflow(where, (uint64_t)(bit - 1) * 8, &address))
                        return dl_fail("ELF RELR overflow");
                    uint64_t *p = dl_pointer(m, address, 8, DL_W);
                    if (!p)
                        return dl_fail("invalid ELF RELR bitmap target");
                    uint64_t value;
                    memcpy(&value, p, 8);
                    value += m->bias;
                    memcpy(p, &value, 8);
                }
            if (dl_add_overflow(where, 63 * 8, &where))
                return dl_fail("ELF RELR overflow");
        }
    }
    return true;
}
static char *dl_origin_path(dl_module *requester, const char *directory, size_t bytes, const char *name)
{
    const char *path = requester ? requester->path : dl_main.path;
    const char *slash = strrchr(path, '/');
    size_t origin = slash ? (size_t)(slash - path) : 1;
    if (!origin)
        origin = 1;
    const char *origin_text = slash ? path : ".";
    size_t expanded = 0, name_bytes = strlen(name);
    if (name_bytes > 16382)
    {
        dl_fail("shared-library name is too long");
        return NULL;
    }
    for (size_t i = 0; i < bytes;)
    {
        size_t skip = 0;
        if (bytes - i >= 7 && !memcmp(directory + i, "$ORIGIN", 7))
            skip = 7;
        else if (bytes - i >= 9 && !memcmp(directory + i, "${ORIGIN}", 9))
            skip = 9;
        size_t amount = skip ? origin : 1;
        if (amount > 16382 - name_bytes - expanded)
        {
            dl_fail("expanded library path is too long");
            return NULL;
        }
        expanded += amount;
        i += skip ? skip : 1;
    }
    size_t need = expanded + name_bytes + 2;
    char *result = malloc(need);
    if (!result)
    {
        dl_fail("out of memory resolving library path");
        return NULL;
    }
    size_t used = 0;
    for (size_t i = 0; i < bytes;)
    {
        size_t skip = 0;
        if (bytes - i >= 7 && !memcmp(directory + i, "$ORIGIN", 7))
            skip = 7;
        else if (bytes - i >= 9 && !memcmp(directory + i, "${ORIGIN}", 9))
            skip = 9;
        if (skip)
        {
            if (origin >= need - used)
            {
                free(result);
                dl_fail("expanded library path is too long");
                return NULL;
            }
            memcpy(result + used, origin_text, origin);
            used += origin;
            i += skip;
        }
        else
            result[used++] = directory[i++];
    }
    if (used)
        result[used++] = '/';
    strcpy(result + used, name);
    return result;
}
static char *dl_search_list(dl_module *requester, const char *list, const char *name)
{
    if (!list)
        return NULL;
    const char *part = list;
    for (;;)
    {
        const char *end = strchr(part, ':');
        size_t count = end ? (size_t)(end - part) : strlen(part);
        char *candidate = dl_origin_path(requester, part, count, name);
        if (!candidate)
            return NULL;
        char *canonical = realpath(candidate, NULL);
        free(candidate);
        if (canonical)
            return canonical;
        if (!end)
            break;
        part = end + 1;
    }
    return NULL;
}
static char *dl_find_path(dl_module *requester, const char *name)
{
    if (strchr(name, '/'))
        return realpath(name, NULL);
    char *found = NULL;
    char **environment = alix_environment_copy();
    if (!environment)
    {
        dl_fail("out of memory snapshotting loader environment");
        return NULL;
    }
    for (size_t i = 0; environment[i]; ++i)
        if (!strncmp(environment[i], "LD_LIBRARY_PATH=", 16))
        {
            found = dl_search_list(requester, environment[i] + 16, name);
            break;
        }
    alix_environment_free(environment);
    if (found || dl_pending)
        return found;
    if (requester)
    {
        found = dl_search_list(requester, requester->runpath ? requester->runpath : requester->rpath, name);
        if (found || dl_pending)
            return found;
    }
    if (requester != &dl_main && (!requester || !requester->runpath) && !dl_main.runpath)
    {
        found = dl_search_list(&dl_main, dl_main.rpath, name);
        if (found || dl_pending)
            return found;
    }
    return dl_search_list(requester, "/usr/lib:/lib", name);
}
static bool dl_read_exact(int fd, void *buffer, size_t bytes, uint64_t offset)
{
    size_t done = 0;
    while (done < bytes)
    {
        size_t count = bytes - done;
        if (count > 65536)
            count = 65536;
        if (offset > INT64_MAX || done > INT64_MAX - offset)
            return false;
        ssize_t got = pread(fd, (char *)buffer + done, count, (off_t)(offset + done));
        if (got <= 0 || (size_t)got > count)
            return false;
        done += (size_t)got;
    }
    return true;
}

static bool dl_map_file(dl_module *m)
{
    /* A concurrent spawn must not inherit the temporary image descriptor. */
    int fd = open(m->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return dl_fail("cannot open shared library");
    dl_ehdr header;
    bool ok = dl_read_exact(fd, &header, sizeof(header), 0);
    if (!ok || memcmp(header.ident, "\177ELF\2\1\1", 7) || header.type != 3 || header.machine != 62 ||
        header.version != 1 || header.ehsize != sizeof(header) || header.phentsize != sizeof(dl_phdr) ||
        !header.phnum || header.phnum > 1024)
    {
        close(fd);
        return dl_fail("not a native x86-64 ELF shared object");
    }
    struct stat metadata;
    if (fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) || (uint64_t)metadata.st_size > INT64_MAX)
    {
        close(fd);
        return dl_fail("cannot size shared object");
    }
    uint64_t file_bytes = (uint64_t)metadata.st_size;
    if (header.phoff > file_bytes || header.phnum > (file_bytes - header.phoff) / sizeof(dl_phdr))
    {
        close(fd);
        return dl_fail("truncated ELF program headers");
    }
    dl_phdr *headers = calloc(header.phnum, sizeof(*headers));
    if (!headers)
    {
        close(fd);
        return dl_fail("out of memory reading ELF headers");
    }
    if (!dl_read_exact(fd, headers, sizeof(*headers) * header.phnum, header.phoff))
    {
        free(headers);
        close(fd);
        return dl_fail("cannot read ELF program headers");
    }
    uint64_t low = UINT64_MAX, high = 0, alignment = DL_PAGE;
    dl_phdr *dynamic = NULL, *tls = NULL, *relro = NULL;
    m->segments = calloc(header.phnum, sizeof(*m->segments));
    if (!m->segments)
    {
        free(headers);
        close(fd);
        return dl_fail("out of memory tracking ELF segments");
    }
    for (unsigned i = 0; i < header.phnum; ++i)
    {
        dl_phdr *p = &headers[i];
        uint64_t end;
        if (p->type == DL_INTERP)
        {
            dl_fail("shared object requests an interpreter");
            goto failed;
        }
        if (p->type == DL_DYNAMIC)
        {
            if (dynamic)
            {
                dl_fail("multiple ELF dynamic segments");
                goto failed;
            }
            dynamic = p;
        }
        if (p->type == DL_TLS)
        {
            if (tls)
            {
                dl_fail("multiple ELF TLS segments");
                goto failed;
            }
            tls = p;
        }
        if (p->type == DL_RELRO)
        {
            if (relro)
            {
                dl_fail("multiple ELF RELRO segments");
                goto failed;
            }
            relro = p;
        }
        if (p->type != DL_LOAD)
            continue;
        if (p->filesz > p->memsz || p->offset > file_bytes || p->filesz > file_bytes - p->offset ||
            dl_add_overflow(p->vaddr, p->memsz, &end) || end > UINT64_MAX - (DL_PAGE - 1) ||
            (p->align && ((p->align & (p->align - 1)) || p->vaddr % p->align != p->offset % p->align)) ||
            ((p->flags & (DL_W | DL_X)) == (DL_W | DL_X)))
        {
            dl_fail("invalid ELF load segment");
            goto failed;
        }
        if (!p->memsz)
            continue;
        for (size_t j = 0; j < m->segment_count; ++j)
        {
            dl_phdr *q = &m->segments[j];
            if (p->vaddr < q->vaddr + q->memsz && q->vaddr < end)
            {
                dl_fail("overlapping ELF load segments");
                goto failed;
            }
        }
        m->segments[m->segment_count++] = *p;
        if ((p->vaddr & ~UINT64_C(4095)) < low)
            low = p->vaddr & ~UINT64_C(4095);
        if (((end + 4095) & ~UINT64_C(4095)) > high)
            high = (end + 4095) & ~UINT64_C(4095);
        if (p->align > alignment)
            alignment = p->align;
    }
    if (!dynamic || !m->segment_count || high <= low || high - low > SIZE_MAX - alignment ||
        alignment > SIZE_MAX / 2)
    {
        dl_fail("invalid ELF load span");
        goto failed;
    }
    m->span = (size_t)(high - low);
    size_t reservation = m->span + (size_t)alignment;
    void *area = mmap(NULL, reservation, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (area == MAP_FAILED)
    {
        dl_fail("cannot reserve shared-object memory");
        goto failed;
    }
    uintptr_t start = (uintptr_t)area + (((uintptr_t)low - (uintptr_t)area) & (uintptr_t)(alignment - 1));
    m->reservation = (uintptr_t)area;
    m->reservation_bytes = reservation;
    m->low = start;
    m->high = start + m->span;
    m->bias = start - (uintptr_t)low;
    unsigned char *permissions = calloc(m->span / DL_PAGE, 1);
    if (!permissions)
    {
        dl_fail("out of memory tracking ELF page permissions");
        goto failed;
    }
    for (size_t i = 0; i < m->segment_count; ++i)
    {
        dl_phdr *p = &m->segments[i];
        size_t first = (p->vaddr - low) / DL_PAGE, last = (p->vaddr + p->memsz - low + 4095) / DL_PAGE;
        for (size_t page = first; page < last; ++page)
            permissions[page] |= (unsigned char)(p->flags | DL_R);
    }
    /* Read-only load pages need no relocation writes. Retain the native file
     * mapping instead of copying the same engine into every browser process.
     * The kernel shares its cache and faults pages in as they are used. Keep
     * mixed-protection boundary pages and BSS-bearing segments private. */
    for (size_t i = 0; i < m->segment_count; ++i)
    {
        dl_phdr *p = &m->segments[i];
        if (!p->filesz || p->vaddr % DL_PAGE != p->offset % DL_PAGE)
            continue;
        size_t first = (p->vaddr - low) / DL_PAGE;
        size_t last = (p->vaddr + p->filesz - low + DL_PAGE - 1) / DL_PAGE;
        bool compatible = true;
        for (size_t page = first; page < last; ++page)
            if (permissions[page] != (unsigned char)(p->flags | DL_R)) compatible = false;
        if (!compatible) continue;
        bool shared = !(p->flags & DL_W) && p->filesz == p->memsz;
        void *target = (void *)(start + first * DL_PAGE);
        if (mmap(target, (last - first) * DL_PAGE, shared ? PROT_READ : PROT_READ | PROT_WRITE,
                 (shared ? MAP_SHARED : MAP_PRIVATE) | MAP_FIXED, fd,
                 (off_t)(p->offset & ~(uint64_t)(DL_PAGE - 1))) == MAP_FAILED)
        {
            free(permissions);
            dl_fail("cannot map ELF load segment");
            goto failed;
        }
        for (size_t page = first; page < last; ++page)
            permissions[page] |= DL_FILE_PAGE | (shared ? DL_SHARED_PAGE : 0);
        if (p->memsz > p->filesz)
        {
            size_t tail = DL_PAGE - (p->vaddr + p->filesz) % DL_PAGE;
            if (tail == DL_PAGE) tail = 0;
            if (tail > p->memsz - p->filesz) tail = p->memsz - p->filesz;
            if (tail) memset((void *)(m->bias + p->vaddr + p->filesz), 0, tail);
        }
    }
    for (size_t page = 0; page < m->span / DL_PAGE;)
    {
        unsigned char flags = permissions[page];
        size_t end = page + 1;
        while (end < m->span / DL_PAGE && permissions[end] == flags)
            ++end;
        if ((flags & (DL_W | DL_X)) == (DL_W | DL_X) ||
            (flags && !(flags & DL_FILE_PAGE) &&
             mprotect((void *)(start + page * DL_PAGE), (end - page) * DL_PAGE, PROT_READ | PROT_WRITE)))
        {
            free(permissions);
            dl_fail("cannot prepare ELF pages");
            goto failed;
        }
        page = end;
    }
    for (size_t i = 0; i < m->segment_count; ++i)
    {
        dl_phdr *p = &m->segments[i];
        if (permissions[(p->vaddr - low) / DL_PAGE] & DL_FILE_PAGE) continue;
        if (p->filesz && !dl_read_exact(fd, (void *)(m->bias + p->vaddr), p->filesz, p->offset))
        {
            free(permissions);
            dl_fail("cannot read ELF load segment");
            goto failed;
        }
    }
    free(permissions);
    if (!dynamic->memsz || dynamic->vaddr % _Alignof(dl_dyn) || dynamic->memsz % sizeof(dl_dyn) ||
        !(m->dynamic = dl_pointer(m, dynamic->vaddr, dynamic->memsz, DL_R)))
    {
        dl_fail("invalid ELF dynamic segment");
        goto failed;
    }
    m->dynamic_count = dynamic->memsz / sizeof(dl_dyn);
    if (tls && tls->memsz)
    {
        if (tls->filesz > tls->memsz || (tls->align && (tls->align & (tls->align - 1))) ||
            !dl_pointer(m, tls->vaddr, tls->filesz, DL_R))
        {
            dl_fail("invalid ELF TLS template");
            goto failed;
        }
        m->tls_image = m->bias + tls->vaddr;
        m->tls_filesz = tls->filesz;
        m->tls_memsz = tls->memsz;
        m->tls_align = tls->align ? tls->align : 1;
        m->tls_skew = tls->vaddr & (m->tls_align - 1);
    }
    if (relro && relro->memsz)
    {
        if (!dl_pointer(m, relro->vaddr, relro->memsz, DL_R))
        {
            dl_fail("invalid ELF RELRO range");
            goto failed;
        }
        m->relro_address = m->bias + relro->vaddr;
        m->relro_bytes = relro->memsz;
    }
    m->program_headers = headers;
    m->program_header_count = header.phnum;
    close(fd);
    return dl_meta(m);
failed:
    free(headers);
    close(fd);
    return false;
}
static bool dl_protect(dl_module *m)
{
    size_t pages = m->span / DL_PAGE;
    unsigned char *permissions = calloc(pages, 1);
    if (!permissions)
        return dl_fail("out of memory protecting ELF pages");
    for (size_t i = 0; i < m->segment_count; ++i)
    {
        dl_phdr *p = &m->segments[i];
        size_t first = (m->bias + p->vaddr - m->low) / DL_PAGE,
               last = (m->bias + p->vaddr + p->memsz - m->low + 4095) / DL_PAGE;
        for (size_t page = first; page < last; ++page)
            permissions[page] |= (unsigned char)(p->flags | DL_R);
    }
    if (m->relro_bytes)
    {
        size_t first = ((m->relro_address & ~(uintptr_t)4095) - m->low) / DL_PAGE,
               last = (((m->relro_address + m->relro_bytes) & ~(uintptr_t)4095) - m->low) / DL_PAGE;
        for (size_t page = first; page < last; ++page)
            permissions[page] &= (unsigned char)~DL_W;
    }
    for (size_t page = 0; page < pages;)
    {
        unsigned char flags = permissions[page];
        size_t end = page + 1;
        while (end < pages && permissions[end] == flags)
            ++end;
        int prot =
            (flags & DL_R ? PROT_READ : 0) | (flags & DL_W ? PROT_WRITE : 0) | (flags & DL_X ? PROT_EXEC : 0);
        if (mprotect((void *)(m->low + page * DL_PAGE), (end - page) * DL_PAGE, prot))
        {
            free(permissions);
            return dl_fail("cannot set ELF page permissions");
        }
        page = end;
    }
    free(permissions);
    return true;
}
static dl_module *dl_load(const char *name, dl_module *requester, dl_module *scope, int flags, unsigned depth)
{
    if (depth >= DL_MODULE_LIMIT)
    {
        dl_fail("too many nested shared libraries");
        return NULL;
    }
    for (dl_module *existing = dl_modules; existing; existing = existing->next)
        if (!strcmp(name, existing->path) ||
            (!strchr(name, '/') && existing->soname && !strcmp(name, existing->soname)))
        {
            if (existing->retiring)
            {
                dl_fail("shared object is awaiting memory retirement");
                return NULL;
            }
            return existing;
        }
    char *path = dl_find_path(requester, name);
    if (!path)
    {
        if (!dl_pending)
        {
            snprintf(dl_message, sizeof(dl_message), "shared library not found: %.210s", name);
            dl_pending = true;
        }
        return NULL;
    }
    size_t count = 0;
    for (dl_module *m = dl_modules; m; m = m->next)
    {
        ++count;
        if (!strcmp(path, m->path))
        {
            free(path);
            if (m->retiring)
            {
                dl_fail("shared object is awaiting memory retirement");
                return NULL;
            }
            return m;
        }
    }
    if (flags & RTLD_NOLOAD)
    {
        free(path);
        dl_fail("shared library is not loaded");
        return NULL;
    }
    if (count >= DL_MODULE_LIMIT || dl_next_id == UINT64_MAX)
    {
        free(path);
        dl_fail("too many shared libraries");
        return NULL;
    }
    dl_module *m = calloc(1, sizeof(*m));
    if (!m)
    {
        free(path);
        dl_fail("out of memory loading shared library");
        return NULL;
    }
    m->path = path;
    m->id = dl_next_id++;
    m->deep = (flags & RTLD_DEEPBIND) != 0;
    m->busy = 1;
    dl_module **tail = &dl_modules;
    while (*tail)
        tail = &(*tail)->next;
    *tail = m;
    if (!scope)
        scope = m;
    if (!dl_map_file(m))
        goto failed;
    if (m->dependency_count)
    {
        m->dependencies = calloc(m->dependency_count, sizeof(*m->dependencies));
        if (!m->dependencies)
        {
            dl_fail("out of memory tracking ELF dependencies");
            goto failed;
        }
    }
    size_t dependency = 0;
    for (size_t i = 0; i < m->dynamic_count && m->dynamic[i].tag; ++i)
        if (m->dynamic[i].tag == DL_NEEDED)
        {
            const char *needed = dl_string(m, m->dynamic[i].value);
            if (!needed)
            {
                dl_fail("invalid ELF dependency name");
                goto failed;
            }
            dl_module *dep = dl_load(needed, m, scope, flags & ~RTLD_NOLOAD, depth + 1);
            if (!dep)
                goto failed;
            m->dependencies[dependency++] = dep;
        }
    m->busy = 0;
    return m;
failed:
    m->busy = 0;
    return NULL;
}
static bool dl_callable(uintptr_t address)
{
    if (!address || address == UINTPTR_MAX)
        return true;
    dl_module *owner = dl_by_address(address);
    if (!owner)
        return dl_fail("ELF initializer is outside a loaded image");
    for (size_t i = 0; i < owner->segment_count; ++i)
    {
        dl_phdr *p = &owner->segments[i];
        if ((p->flags & DL_X) && address >= owner->bias + p->vaddr &&
            address - (owner->bias + p->vaddr) < p->memsz)
        {
            return true;
        }
    }
    return dl_fail("ELF initializer is not executable");
}

static bool dl_call(uintptr_t address)
{
    if (!dl_callable(address))
        return false;
    if (address && address != UINTPTR_MAX)
        ((void (*)(void))address)();
    return true;
}

static bool dl_validate_initializers(void)
{
    for (dl_module *m = dl_modules; m; m = m->next)
    {
        if (m->initialized || m->initializing || !m->relocated)
            continue;
        if ((m->init && !dl_callable(m->bias + m->init)) || (m->fini && !dl_callable(m->bias + m->fini)))
            return false;
        uintptr_t *init = m->init_bytes ? dl_pointer(m, m->init_array, m->init_bytes, DL_R) : NULL;
        uintptr_t *fini = m->fini_bytes ? dl_pointer(m, m->fini_array, m->fini_bytes, DL_R) : NULL;
        for (size_t i = 0; i < m->init_bytes / 8; ++i)
            if (!dl_callable(init[i]))
                return false;
        for (size_t i = 0; i < m->fini_bytes / 8; ++i)
            if (!dl_callable(fini[i]))
                return false;
    }
    return true;
}

static bool dl_relocate_group(dl_module *scope)
{
    /* Every dependency edge must exist before any symbol lookup. In particular,
     * a dependency can refer to itself or back into a cyclic parent. */
    for (dl_module *m = dl_modules; m; m = m->next)
    {
        if (m->relocated)
            continue;
        if (!dl_versions_requirements(m) || !dl_relocate_table(m, scope, m->rela, m->rela_bytes) ||
            !dl_relocate_table(m, scope, m->jmprel, m->jmp_bytes) || !dl_relocate_packed(m) ||
            (!m->main && !dl_protect(m)))
            return false;
        m->relocated = true;
    }
    return dl_validate_initializers();
}
static bool dl_initialize(dl_module *m)
{
    if (m->initialized || m->initializing)
        return true;
    if (!m->relocated)
        return dl_fail("shared object is not relocated");
    m->initializing = true;
    ++m->busy;
    for (size_t i = 0; i < m->dependency_count; ++i)
        if (!dl_initialize(m->dependencies[i]))
            goto failed;
    if (m->init && !dl_call(m->bias + m->init))
        goto failed;
    uintptr_t *array = m->init_bytes ? dl_pointer(m, m->init_array, m->init_bytes, DL_R) : NULL;
    for (size_t i = 0; i < m->init_bytes / 8; ++i)
        if (!dl_call(array[i]))
            goto failed;
    m->initialized = true;
    m->initializing = false;
    m->sequence = ++dl_sequence;
    --m->busy;
    return true;
failed:
    m->initializing = false;
    --m->busy;
    return false;
}
static void dl_mark(void)
{
    for (dl_module *m = dl_modules; m; m = m->next)
        m->mark = !m->retiring &&
                  (m->main || m->external || m->tls_users || (m->nodelete && m->initialized) || m->busy);
    bool changed;
    do
    {
        changed = false;
        for (dl_module *m = dl_modules; m; m = m->next)
            if (m->mark)
            {
                for (size_t i = 0; i < m->dependency_count; ++i)
                    if (m->dependencies && m->dependencies[i] && !m->dependencies[i]->mark)
                    {
                        m->dependencies[i]->mark = true;
                        changed = true;
                    }
                for (size_t i = 0; i < m->binding_count; ++i)
                    if (!m->bindings[i]->mark)
                    {
                        m->bindings[i]->mark = true;
                        changed = true;
                    }
            }
    } while (changed);
}
static void dl_collect(void)
{
    if (dl_collecting)
        return;
    dl_collecting = true;
    for (;;)
    {
        dl_mark();
        dl_module *last = NULL;
        for (dl_module *m = dl_modules; m; m = m->next)
            if (!m->mark && m->initialized && !m->finalized && (!last || m->sequence > last->sequence))
                last = m;
        if (!last)
            break;
        last->finalized = true;
        ++last->busy;
        uintptr_t *array = last->fini_bytes ? dl_pointer(last, last->fini_array, last->fini_bytes, DL_R) : NULL;
        for (size_t i = last->fini_bytes / 8; i; --i)
            (void)dl_call(array[i - 1]);
        if (last->fini)
            (void)dl_call(last->bias + last->fini);
        --last->busy;
    }
    dl_mark();
    dl_module **cursor = &dl_modules;
    while (*cursor)
    {
        dl_module *m = *cursor;
        if (m->mark)
        {
            cursor = &m->next;
            continue;
        }
        m->retiring = true;
        if (m->reservation && munmap((void *)m->reservation, m->reservation_bytes))
        {
            /* VM retirement can fail before publication under memory pressure.
             * Hide the image but retain its ownership for the next collection. */
            cursor = &m->next;
            continue;
        }
        *cursor = m->next;
        free(m->segments);
        free((void *)m->program_headers);
        free(m->dependencies);
        free(m->bindings);
        free(m->versions);
        free(m->path);
        free(m);
    }
    dl_collecting = false;
}
static void dl_at_exit(void)
{
    dl_lock();
    /* Process termination runs finalizers even for NODELETE/TLS-pinned images.
     * Keep code mapped for remaining exit handlers and terminating threads. */
    for (;;)
    {
        dl_module *last = NULL;
        for (dl_module *m = dl_modules; m; m = m->next)
            if (!m->main && m->initialized && !m->finalized && (!last || m->sequence > last->sequence))
                last = m;
        if (!last)
            break;
        last->finalized = true;
        ++last->busy;
        uintptr_t *array = last->fini_bytes ? dl_pointer(last, last->fini_array, last->fini_bytes, DL_R) : NULL;
        for (size_t i = last->fini_bytes / 8; i; --i)
            (void)dl_call(array[i - 1]);
        if (last->fini)
            (void)dl_call(last->bias + last->fini);
        --last->busy;
    }
    dl_unlock();
}

int __attribute__((visibility("default"))) __alix_dynamic_startup(int initialize)
{
    if (!dl_startup_dynamic) return 0;
    dl_pending = false;
    dl_lock();
    if (!dl_main_initialize()) goto failed;
    if (!initialize && !dl_startup_mapped)
    {
        if (dl_main.dependency_count > DL_MODULE_LIMIT)
        {
            dl_fail("too many executable startup libraries");
            goto failed;
        }
        if (dl_main.dependency_count)
        {
            dl_main.dependencies = calloc(dl_main.dependency_count, sizeof(*dl_main.dependencies));
            if (!dl_main.dependencies)
            {
                dl_fail("out of memory tracking executable startup libraries");
                goto failed;
            }
        }
        size_t dependency = 0;
        for (size_t i = 0; i < dl_main.dynamic_count && dl_main.dynamic[i].tag; ++i)
            if (dl_main.dynamic[i].tag == DL_NEEDED)
            {
                const char *name = dl_string(&dl_main, dl_main.dynamic[i].value);
                if (!name || !*name)
                {
                    dl_fail("invalid executable startup library name");
                    goto failed;
                }
                dl_module *module = dl_load(name, &dl_main, &dl_main, RTLD_NOW | RTLD_GLOBAL, 0);
                if (!module) goto failed;
                dl_main.dependencies[dependency++] = module;
            }
        for (dl_module *module = dl_modules; module; module = module->next)
            module->global = true;
        if (!dl_relocate_group(&dl_main)) goto failed;
        dl_startup_mapped = true;
    }
    if (initialize)
    {
        if (!dl_startup_mapped)
        {
            dl_fail("executable startup libraries were not relocated");
            goto failed;
        }
        for (size_t i = 0; i < dl_main.dependency_count; ++i)
            if (!dl_initialize(dl_main.dependencies[i])) goto failed;
        if (!dl_exit_registered)
        {
            if (atexit(dl_at_exit))
            {
                dl_fail("cannot register startup library finalizers");
                goto failed;
            }
            dl_exit_registered = true;
        }
    }
    dl_unlock();
    return 0;
failed:
    dl_fail("cannot initialize executable startup libraries");
    dl_unlock();
    size_t bytes = strnlen(dl_message, sizeof(dl_message) - 2);
    dl_message[bytes++] = '\n';
    sys_serial_write(dl_message, bytes);
    return -1;
}

void *dlopen(const char *path, int flags)
{
    dl_pending = false;
    int known = RTLD_LAZY | RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE | RTLD_NOLOAD | RTLD_DEEPBIND;
    if ((flags & ~known) || !(flags & (RTLD_LAZY | RTLD_NOW)))
    {
        dl_fail("invalid dynamic-loader flags");
        return NULL;
    }
    dl_lock();
    if (!dl_main_initialize())
    {
        dl_unlock();
        return NULL;
    }
    dl_collect();
    dl_module *caller = dl_by_address((uintptr_t)__builtin_return_address(0));
    dl_module *m = path ? dl_load(path, caller, NULL, flags, 0) : &dl_main;
    if (!m || !dl_relocate_group(m))
    {
        dl_collect();
        dl_unlock();
        return NULL;
    }
    if (m->external == UINT32_MAX)
    {
        dl_fail("shared-library reference overflow");
        dl_unlock();
        return NULL;
    }
    ++m->external;
    if (flags & RTLD_GLOBAL)
    {
        m->global = true;
        bool changed;
        do
        {
            changed = false;
            for (dl_module *p = dl_modules; p; p = p->next)
                if (p->global)
                    for (size_t i = 0; i < p->dependency_count; ++i)
                        if (p->dependencies && p->dependencies[i] && !p->dependencies[i]->global)
                        {
                            p->dependencies[i]->global = true;
                            changed = true;
                        }
        } while (changed);
    }
    if (!dl_initialize(m))
    {
        --m->external;
        dl_collect();
        dl_unlock();
        return NULL;
    }
    m->nodelete |= (flags & RTLD_NODELETE) != 0;
    if (!dl_exit_registered)
    {
        if (atexit(dl_at_exit))
        {
            --m->external;
            dl_fail("cannot register shared-library cleanup");
            dl_collect();
            dl_unlock();
            return NULL;
        }
        dl_exit_registered = true;
    }
    dl_unlock();
    return m;
}
int dlclose(void *handle)
{
    dl_pending = false;
    dl_lock();
    dl_module *m = dl_modules;
    while (m && m != handle)
        m = m->next;
    if (!m || m->retiring || !m->external)
    {
        dl_fail("invalid shared-library handle");
        dl_unlock();
        return -1;
    }
    --m->external;
    dl_collect();
    dl_unlock();
    return 0;
}
static void *dl_lookup_symbol(void *handle,const char *name,const dl_version_info *version,uintptr_t caller_address)
{
    dl_pending = false;
    if (!name)
    {
        dl_fail("null dynamic symbol name");
        return NULL;
    }
    dl_lock();
    if (!dl_main_initialize())
    {
        dl_unlock();
        return NULL;
    }
    dl_module *owner = NULL, *scope = NULL;
    dl_sym *symbol = NULL;
    if (handle == RTLD_DEFAULT)
    {
        scope = dl_by_address(caller_address);
        symbol = dl_resolve_version(scope, name, version, &owner);
    }
    else if (handle == RTLD_NEXT)
    {
        dl_module *caller = dl_by_address(caller_address);
        for (dl_module *m = caller ? caller->next : NULL; m; m = m->next)
            if (m->global && (symbol = dl_own_symbol_version(m, name, version)))
            {
                owner = m;
                break;
            }
    }
    else
    {
        for (dl_module *m = dl_modules; m; m = m->next)
            if (m == handle && !m->retiring)
            {
                scope = m;
                break;
            }
        if (scope)
            symbol = dl_group_symbol_version(scope, name, version, &owner);
        else
            dl_fail("invalid shared-library handle");
    }
    uintptr_t address = 0;
    if (symbol)
    {
        if (!dl_symbol_address(owner, symbol, &address))
            address = 0;
    }
    else if (!dl_pending)
    {
        snprintf(dl_message, sizeof(dl_message), "dynamic symbol not found: %.210s", name);
        dl_pending = true;
    }
    dl_unlock();
    return (void *)address;
}

void *dlsym(void *handle,const char *name)
{
    return dl_lookup_symbol(handle,name,NULL,(uintptr_t)__builtin_return_address(0));
}
void *dlvsym(void *handle,const char *name,const char *version)
{
    dl_pending=false;
    if(!version || !*version){dl_fail("null or empty dynamic symbol version");return NULL;}
    dl_version_info requested={.name=version,.hash=dl_hash_name(version)};
    return dl_lookup_symbol(handle,name,&requested,(uintptr_t)__builtin_return_address(0));
}

char *dlerror(void)
{
    if (!dl_pending)
        return NULL;
    dl_pending = false;
    return dl_message;
}
int dladdr(const void *address, Dl_info *information)
{
    dl_pending = false;
    if (!information)
        return 0;
    dl_lock();
    if (!dl_main_initialize())
    {
        dl_unlock();
        return 0;
    }
    dl_module *m = dl_by_address((uintptr_t)address);
    if (!m)
    {
        dl_unlock();
        return 0;
    }
    *information = (Dl_info){.dli_fname = m->path, .dli_fbase = (void *)m->low};
    uintptr_t nearest = 0;
    for (size_t i = 1; i < m->symbol_count; ++i)
    {
        dl_sym *s = &m->symbols[i];
        unsigned binding = s->info >> 4;
        if (!s->section || (s->info & 15) == 6 || (binding != 1 && binding != 2))
            continue;
        uintptr_t value = s->section == 0xfff1 ? s->value : m->bias + s->value;
        const char *name = dl_string(m, s->name);
        if (name && value <= (uintptr_t)address && value >= nearest &&
            (!s->size || (uintptr_t)address - value < s->size) && dl_by_address(value) == m)
        {
            nearest = value;
            information->dli_sname = name;
            information->dli_saddr = (void *)value;
        }
    }
    dl_unlock();
    return 1;
}

int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *context)
{
    if (!callback) { errno = EINVAL; return -1; }
    typedef struct { dl_module *module; struct dl_phdr_info info; } snapshot_t;
    dl_lock();
    if (!dl_main_initialize()) { dl_unlock(); errno = ENOMEM; return -1; }
    size_t count = 0;
    for (dl_module *m = dl_modules; m; m = m->next)
        if (!m->retiring && m->relocated && m->program_header_count) ++count;
    snapshot_t *snapshots = calloc(count ? count : 1, sizeof(*snapshots));
    if (!snapshots) { dl_unlock(); errno = ENOMEM; return -1; }
    size_t index = 0;
    for (dl_module *m = dl_modules; m; m = m->next)
    {
        if (m->retiring || !m->relocated || !m->program_header_count) continue;
        ++m->busy;
        snapshots[index++] = (snapshot_t){.module = m, .info = {
            .dlpi_addr = m->bias, .dlpi_name = m->main ? "" : m->path,
            .dlpi_phdr = (const Elf64_Phdr *)m->program_headers,
            .dlpi_phnum = (Elf64_Half)m->program_header_count}};
    }
    dl_unlock();
    /* User callbacks can open/close libraries or join a different loader user.
     * Each image and its immutable metadata remain pinned across callbacks. */
    int result = 0;
    for (index = 0; index < count && !result; ++index)
        result = callback(&snapshots[index].info, sizeof(snapshots[index].info), context);
    dl_lock();
    for (index = 0; index < count; ++index) --snapshots[index].module->busy;
    free(snapshots);
    dl_collect();
    dl_unlock();
    return result;
}
