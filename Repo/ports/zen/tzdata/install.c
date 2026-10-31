#include "userlib.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/stat.h"
#include "crypto/sha256.h"
#include "serial.h"
#include "package_config.h"

/* Staging only: no activation/config updates, no existing-file truncation, and
 * no deletion. The versioned namespace must have a single installer/writer;
 * Alix does not yet expose O_EXCL, rename or fsync to make stronger guarantees. */
typedef struct
{
    const uint8_t *data, *hash;
    char *name;
    uint32_t size;
} package_entry_t;

typedef struct
{
    uint8_t *bundle, *io;
    package_entry_t *entries;
    syscall_dirent_t *listing;
    size_t listing_capacity;
    sha256_ctx_t hash;
    uint8_t digest[32];
    char *root;
} installer_t;

static uint32_t read_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int hex_digit(char value)
{
    return value >= '0' && value <= '9' ? value-'0' : value >= 'a' && value <= 'f' ? value-'a'+10 : -1;
}

static int digest_matches_hex(const uint8_t *value,const char *hex)
{
    for(unsigned i=0;i<32;++i)
        if(hex_digit(hex[2*i])<0 || hex_digit(hex[2*i+1])<0 ||
           value[i] != (uint8_t)(16*hex_digit(hex[2*i])+hex_digit(hex[2*i+1]))) return 0;
    return hex[64]==0;
}

static int safe_name(const char *name,size_t length)
{
    if(!length || length>255 || name[0]=='/' || name[length-1]=='/') return 0;
    size_t start=0;
    for(size_t i=0;i<=length;++i)
    {
        unsigned char c=i<length ? (unsigned char)name[i] : '/';
        if(c=='/')
        {
            size_t part=i-start;
            if(!part || (part==1 && name[start]=='.') ||
               (part==2 && name[start]=='.' && name[start+1]=='.')) return 0;
            start=i+1;
        }
        else if(!((c>='a' && c<='z') || (c>='A' && c<='Z') ||
                  (c>='0' && c<='9') || c=='_' || c=='+' || c=='.' || c=='-')) return 0;
    }
    return 1;
}

static int load_bundle(installer_t *state,const char *path)
{
    FILE *file=fopen(path,"rb");
    if(!file) return 0;
    state->bundle=malloc(TZ_PACKAGE_SIZE+1u);
    if(!state->bundle) { fclose(file); return 0; }
    size_t received=fread(state->bundle,1,TZ_PACKAGE_SIZE+1u,file);
    int failed=ferror(file); fclose(file);
    if(failed || received!=TZ_PACKAGE_SIZE) return 0;
    sha256_digest(state->bundle,received,state->digest);
    if(!digest_matches_hex(state->digest,TZ_PACKAGE_SHA256) || memcmp(state->bundle,"ALIXTZP1",8) ||
       read_u32(state->bundle+8)!=1 || read_u32(state->bundle+12)!=TZ_PACKAGE_ENTRIES) return 0;
    state->entries=calloc(TZ_PACKAGE_ENTRIES,sizeof(*state->entries));
    if(!state->entries) return 0;
    size_t offset=16;
    for(unsigned i=0;i<TZ_PACKAGE_ENTRIES;++i)
    {
        if(offset>received || received-offset<40) return 0;
        uint32_t name_length=read_u32(state->bundle+offset),length=read_u32(state->bundle+offset+4);
        state->entries[i].hash=state->bundle+offset+8;
        offset+=40;
        if(name_length>received-offset || !safe_name((char *)state->bundle+offset,name_length)) return 0;
        state->entries[i].name=malloc((size_t)name_length+1);
        if(!state->entries[i].name) return 0;
        memcpy(state->entries[i].name,state->bundle+offset,name_length);
        state->entries[i].name[name_length]=0;
        if(i && strcmp(state->entries[i-1].name,state->entries[i].name)>=0) return 0;
        offset+=name_length;
        if(length>received-offset) return 0;
        state->entries[i].data=state->bundle+offset;
        state->entries[i].size=length;
        sha256_digest(state->entries[i].data,length,state->digest);
        if(memcmp(state->digest,state->entries[i].hash,32)) return 0;
        offset+=length;
    }
    return offset==received;
}

/* Inspect each path component using directory-entry types. Resolve /usr to
 * its documented physical /root/usr mount before this walk, then reject any
 * further symlink so staging cannot redirect through an existing custom link. */
static int child_type(installer_t *state,const char *directory,const char *name)
{
    for(;;)
    {
        ssize_t count=sys_list_dir(directory,state->listing,state->listing_capacity);
        if(count<0) return -2;
        for(ssize_t i=0;i<count;++i)
            if(!strcmp(state->listing[i].name,name)) return (int)state->listing[i].type;
        if((size_t)count<state->listing_capacity) return -1;
        if(state->listing_capacity>=8192) return -2;
        size_t capacity=state->listing_capacity*2;
        syscall_dirent_t *grown=realloc(state->listing,capacity*sizeof(*grown));
        if(!grown) return -2;
        state->listing=grown; state->listing_capacity=capacity;
    }
}

static int path_type(installer_t *state,char *path,int create_parents)
{
    size_t length=strlen(path),component=1;
    for(size_t end=1;end<=length;++end)
    {
        if(path[end]!='/' && path[end]!=0) continue;
        char saved=path[end]; path[end]=0;
        char *name=path+component;
        int type;
        if(component==1) type=child_type(state,"/",name);
        else
        {
            char separator=path[component-1]; path[component-1]=0;
            type=child_type(state,path,name); path[component-1]=separator;
        }
        if(type==-1 && saved && create_parents)
        {
            if(sys_mkdir(path)!=0) { path[end]=saved; return -2; }
            type=SYSCALL_NODE_TYPE_DIR;
        }
        path[end]=saved;
        if(!saved || type<0) return type;
        if(type!=SYSCALL_NODE_TYPE_DIR) return -2;
        component=end+1;
    }
    return -2;
}

static char *entry_path(installer_t *state,const char *name)
{
    size_t base=strlen(state->root),length=strlen(name);
    char *path=malloc(base+length+2);
    if(path) { memcpy(path,state->root,base); path[base]='/'; memcpy(path+base+1,name,length+1); }
    return path;
}

static int verify_file(installer_t *state,const char *path,size_t size,const uint8_t hash[32])
{
    FILE *file=fopen(path,"rb");
    if(!file) return 0;
    sha256_init(&state->hash);
    size_t read_total=0;
    for(;;)
    {
        size_t got=fread(state->io,1,65536,file);
        if(!got) break;
        if(read_total>size || got>size-read_total) { fclose(file); return 0; }
        sha256_update(&state->hash,state->io,got); read_total+=got;
    }
    int error=ferror(file); fclose(file);
    sha256_final(&state->hash,state->digest);
    return !error && read_total==size && !memcmp(state->digest,hash,32);
}

static int write_missing(installer_t *state,char *path,const uint8_t *data,size_t size,const uint8_t hash[32])
{
    int type=path_type(state,path,1);
    if(type==SYSCALL_NODE_TYPE_FILE) return verify_file(state,path,size,hash);
    if(type!=-1) return 0;
    /* Do not request truncate. The preflight and immediate recheck preserve
     * existing mismatches; an exclusive-create primitive is still required
     * before allowing concurrent writers to this reserved staging namespace. */
    int fd=open(path,SYSCALL_OPEN_WRITE|SYSCALL_OPEN_CREATE);
    if(fd<0) return 0;
    size_t written=0;
    while(written<size)
    {
        ssize_t count=write(fd,data+written,size-written);
        if(count<=0 || (size_t)count>size-written) { close(fd); return 0; }
        written+=(size_t)count;
    }
    if(close(fd)!=0) return 0;
    return verify_file(state,path,size,hash);
}

static int run_installer(installer_t *state,const char *mode)
{
    int stage=!strcmp(mode,"stage"),verify=!strcmp(mode,"verify"),check=!strcmp(mode,"check");
    if(!stage && !verify && !check) return 0;
    unsigned missing=0,preserved=0,created=0;
    for(unsigned i=0;i<TZ_PACKAGE_ENTRIES;++i)
    {
        package_entry_t *entry=&state->entries[i];
        char *path=entry_path(state,entry->name);
        if(!path) return 0;
        int type=path_type(state,path,0);
        if(type==-1) ++missing;
        else if(type==SYSCALL_NODE_TYPE_FILE && verify_file(state,path,entry->size,entry->hash)) ++preserved;
        else { serial_printf("TZDATA_STAGE: conflict %s\n",path); free(path); return 0; }
        free(path);
    }
    if(check)
    {
        serial_printf("TZDATA_CHECK: PASS release=%s files=%u missing=%u identical=%u\n",TZ_PACKAGE_RELEASE,TZ_PACKAGE_ENTRIES,missing,preserved);
        return 1;
    }
    if(verify && missing) return 0;
    if(stage)
    {
        for(unsigned i=0;i<TZ_PACKAGE_ENTRIES;++i)
        {
            package_entry_t *entry=&state->entries[i];
            char *path=entry_path(state,entry->name);
            if(!path) return 0;
            int type=path_type(state,path,0);
            int okay=write_missing(state,path,entry->data,entry->size,entry->hash);
            free(path);
            if(!okay) return 0;
            if(type==-1) ++created;
        }
    }
    /* Full readback, including metadata and all copied aliases. There is no
     * activation record: successful staging is not a durability claim. */
    for(unsigned i=0;i<TZ_PACKAGE_ENTRIES;++i)
    {
        package_entry_t *entry=&state->entries[i];
        char *path=entry_path(state,entry->name);
        int okay=path && verify_file(state,path,entry->size,entry->hash);
        free(path); if(!okay) return 0;
    }
    serial_printf("TZDATA_%s: PASS release=%s files=%u created=%u identical=%u root=%s\n",
                  stage ? "STAGE" : "VERIFY",TZ_PACKAGE_RELEASE,TZ_PACKAGE_ENTRIES,created,preserved,TZ_PACKAGE_ROOT);
    return 1;
}

int main(int argc,char **argv)
{
    if(argc!=3)
    {
        serial_printf("usage: tzdata_install.elf check|stage|verify <pinned-bundle>\n");
        return 2;
    }
    installer_t *state=calloc(1,sizeof(*state));
    if(!state) return 1;
    state->listing_capacity=64;
    state->listing=calloc(state->listing_capacity,sizeof(*state->listing));
    state->io=malloc(65536);
    state->root=malloc(sizeof(TZ_PACKAGE_ROOT)+sizeof("/root"));
    if(state->root) snprintf(state->root,sizeof(TZ_PACKAGE_ROOT)+sizeof("/root"),"/root%s",TZ_PACKAGE_ROOT);
    int okay=state->listing && state->io && state->root && load_bundle(state,argv[2]) && run_installer(state,argv[1]);
    if(!okay) serial_printf("TZDATA_STAGE: FAIL (existing data preserved; any partial stage remains inactive)\n");
    if(state->entries)
        for(unsigned i=0;i<TZ_PACKAGE_ENTRIES;++i) free(state->entries[i].name);
    free(state->entries); free(state->bundle); free(state->listing); free(state->io); free(state->root); free(state);
    return okay ? 0 : 1;
}
