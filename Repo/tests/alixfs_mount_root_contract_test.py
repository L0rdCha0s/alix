#!/usr/bin/env python3
"""Run the complete production AlixFS backend against a memory block device."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def main():
    source = (ROOT / "src/kernel/alixfs.c").read_text()
    source = "\n".join(line for line in source.splitlines() if not line.startswith("#include"))
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#define CHECK(c) do { if(!(c)) { fprintf(stderr,"AlixFS check line %u: %s\n",__LINE__,#c); abort(); } } while(0)
#define VFS_UID_ROOT 0u
#define VFS_GID_ROOT 0u
#define VFS_PATH_MAX 4096u
static void serial_printf(const char *format, ...) { (void)format; }
typedef struct { bool locked; } spinlock_t;
static void spinlock_init(spinlock_t *l) { l->locked=false; }
static void spinlock_lock(spinlock_t *l) { CHECK(!l->locked); l->locked=true; }
static void spinlock_unlock(spinlock_t *l) { CHECK(l->locked); l->locked=false; }
typedef enum { VFS_NODE_DIR, VFS_NODE_FILE, VFS_NODE_BLOCK, VFS_NODE_SYMLINK } vfs_node_type_t;
typedef struct vfs_node vfs_node_t;
typedef struct vfs_mount { vfs_node_t *mount_point; size_t dirty_bytes; spinlock_t dirty_lock; } vfs_mount_t;
struct vfs_node {
    vfs_node_type_t type; vfs_node_t *parent,*first_child,*next_sibling; vfs_mount_t *mount;
    char *name,*data; size_t size,capacity,pending_dirty_bytes; spinlock_t data_lock;
    bool allow_mutation,dirty,disk_meta_dirty,disk_data_dirty,disk_name_dirty;
    uint32_t disk_id,uid,gid,refcount,permissions; uint64_t atime,mtime,ctime,dirty_seq;
};
/* This backend-only fixture has no mapped pages; native mapping tests cover
 * cache synchronization through the real paging layer. */
static void vfs_mapping_pull_locked(vfs_node_t *node) { CHECK(node->data_lock.locked); }
typedef struct { size_t sector_size; uint64_t sector_count; unsigned char *bytes; bool fail_write; unsigned fail_countdown; unsigned reads; size_t read_bytes; bool fail_read; uint64_t read_limit; } block_device_t;
static bool block_read(block_device_t *d,uint64_t lba,uint32_t count,void *out) {
    CHECK(lba <= d->sector_count && count <= d->sector_count-lba);
    ++d->reads; d->read_bytes += (size_t)count*d->sector_size;
    if(d->fail_read || (d->read_limit && lba+count>d->read_limit)) return false;
    memcpy(out,d->bytes+lba*d->sector_size,(size_t)count*d->sector_size); return true;
}
static bool block_write(block_device_t *d,uint64_t lba,uint32_t count,const void *in) {
    CHECK(lba <= d->sector_count && count <= d->sector_count-lba);
    if(d->fail_write || (d->fail_countdown && !--d->fail_countdown)) return false;
    memcpy(d->bytes+lba*d->sector_size,in,(size_t)count*d->sector_size); return true;
}
typedef struct alixfs_mount alixfs_mount_t;
typedef struct vfs_filesystem_info {
    uint64_t block_size, fragment_size, blocks, free_blocks, available_blocks;
    uint64_t files, free_files, available_files, filesystem_id, flags, name_max;
} vfs_filesystem_info_t;
static bool block_flush(block_device_t *d) { (void)d; return true; }
'''
    code += source + r'''
static char *copy(const char *s) { size_t n=strlen(s)+1; char *p=malloc(n); CHECK(p); memcpy(p,s,n); return p; }
static void free_node(vfs_node_t *n) {
    while(n->first_child) { vfs_node_t *child=n->first_child; n->first_child=child->next_sibling; free_node(child); }
    free(n->name); free(n->data); free(n);
}
static vfs_node_t *new_root(const char *name,vfs_node_t *parent,vfs_mount_t *m) {
    vfs_node_t *n=alixfs_new_node(VFS_NODE_DIR); CHECK(n); n->name=copy(name); n->parent=parent;
    m->mount_point=n; return n;
}
static void legacy_modes(unsigned version) {
    block_device_t *disk=calloc(1,sizeof(*disk));CHECK(disk);disk->sector_size=512;disk->sector_count=8192;
    disk->bytes=calloc(disk->sector_count,512);CHECK(disk->bytes&&alixfs_mount_format(disk));
    /* Produce an old, unextended root record using each supported header. */
    alixfs2_header_t *header=(void *)disk->bytes;header->version=version;
    alixfs2_chunk_entry_t *table=(void *)(disk->bytes+alixfs_align_size(sizeof(*header),512));
    table[header->root_id].length=alixfs_node_disk_header_size(version);
    vfs_mount_t *mount=calloc(1,sizeof(*mount));CHECK(mount);
    vfs_node_t *root=new_root("old",NULL,mount);alixfs_mount_t *fs=alixfs_mount_create(disk);
    CHECK(fs&&alixfs_mount_load(fs,mount)&&root->permissions==0777);
    root->permissions=0750;root->disk_meta_dirty=true;
    CHECK(alixfs_mount_flush_single(fs,root,mount,false)&&alixfs_mount_commit(fs));
    alixfs_mount_destroy(fs);free_node(root);root=new_root("new",NULL,mount);fs=alixfs_mount_create(disk);
    CHECK(fs&&alixfs_mount_load(fs,mount)&&root->permissions==0750);
    /* A recognized extension with an invalid version must fail closed. */
    alixfs_mode_disk_t *mode=(void *)(disk->bytes+fs->chunks[fs->header.root_id].offset+alixfs_node_disk_header_size(version));
    mode->version=2;alixfs_mount_destroy(fs);free_node(root);root=new_root("bad",NULL,mount);fs=alixfs_mount_create(disk);
    CHECK(fs&&!alixfs_mount_load(fs,mount));
    alixfs_mount_destroy(fs);free_node(root);free(mount);free(disk->bytes);free(disk);
}
static void mount_reader_edges(void) {
    block_device_t *disk=calloc(1,sizeof(*disk));CHECK(disk);
    disk->sector_size=512;disk->sector_count=256;disk->bytes=malloc(256*512);CHECK(disk->bytes);
    for(size_t i=0;i<256*512;++i)disk->bytes[i]=(unsigned char)(i*13);
    alixfs_mount_t *fs=alixfs_mount_create(disk);CHECK(fs);
    alixfs_load_state_t *load=calloc(1,sizeof(*load));CHECK(load);
    unsigned char *buffer=malloc(128*1024);CHECK(buffer);
    /* Unaligned reads at the last sector must not read past the device. */
    CHECK(alixfs_mount_read(fs,load,256*512-37,buffer,37));
    CHECK(!memcmp(buffer,disk->bytes+256*512-37,37));
    CHECK(!alixfs_mount_read(fs,load,256*512-37,buffer,38));
    /* A cache hit performs no I/O. */
    unsigned reads=disk->reads;
    CHECK(alixfs_mount_read(fs,load,256*512-20,buffer,20)&&disk->reads==reads);
    /* An unreadable speculative sector must not hide a readable record. */
    disk->read_limit=1;reads=disk->reads;
    CHECK(alixfs_mount_read(fs,load,0,buffer,128)&&!memcmp(buffer,disk->bytes,128));
    CHECK(disk->reads==reads+2&&load->length==0);
    CHECK(!alixfs_mount_read(fs,load,512,buffer,128));
    disk->read_limit=0;
    CHECK(alixfs_mount_read(fs,load,512,buffer,96*1024));
    CHECK(!memcmp(buffer,disk->bytes+512,96*1024));
    free(buffer);free(load);alixfs_mount_destroy(fs);free(disk->bytes);free(disk);
}
static void mount_read_regression(void) {
    block_device_t *disk=calloc(1,sizeof(*disk)); CHECK(disk);
    disk->sector_size=512; disk->sector_count=8192; disk->bytes=calloc(disk->sector_count,512); CHECK(disk->bytes);
    CHECK(alixfs_mount_format(disk));
    vfs_mount_t *mount=calloc(1,sizeof(*mount)); CHECK(mount);
    vfs_node_t *root=new_root("read-test",NULL,mount);
    alixfs_mount_t *fs=alixfs_mount_create(disk); CHECK(fs&&alixfs_mount_load(fs,mount));
    /* Put children before their parent in ID order. The in-memory link pass
     * must still work without fetching their records again. */
    vfs_node_t *dir=alixfs_new_node(VFS_NODE_DIR); CHECK(dir);
    dir->name=copy("directory");dir->disk_id=300;dir->parent=root;dir->mount=mount;root->first_child=dir;
    for(unsigned i=0;i<256;++i) {
        vfs_node_t *file=alixfs_new_node(VFS_NODE_FILE); CHECK(file);
        char name[32];snprintf(name,sizeof(name),"file-%u",i);file->name=copy(name);
        file->disk_id=i+1;file->parent=dir;file->mount=mount;
        file->next_sibling=dir->first_child;dir->first_child=file;
        /* Exercise cache hits, cache refills and direct large reads. */
        file->size=i==128?256*1024:37;file->capacity=file->size+1;
        file->data=malloc(file->capacity);CHECK(file->data);
        memset(file->data,(unsigned char)i,file->size);file->data[file->size]=0;
        CHECK(alixfs_mount_flush_single(fs,file,mount,true));
    }
    CHECK(alixfs_mount_flush_single(fs,dir,mount,true));
    CHECK(alixfs_mount_flush_single(fs,root,mount,true)&&alixfs_mount_commit(fs));
    size_t data_bytes=fs->header.data_region_size;
    alixfs_mount_destroy(fs);free_node(root);
    root=new_root("remounted",NULL,mount);fs=alixfs_mount_create(disk);CHECK(fs);
    disk->reads=0;disk->read_bytes=0;
    CHECK(alixfs_mount_load(fs,mount));
    printf("AlixFS mount reads=%u bytes=%zu\n",disk->reads,disk->read_bytes);fflush(stdout);
    CHECK(disk->reads<32); /* Thousands of tiny requests caused the boot stall. */
    CHECK(disk->read_bytes<data_bytes+fs->header_span+fs->chunk_table_bytes+192*1024); /* Large payload is read once. */
    dir=root->first_child;CHECK(dir&&dir->parent==root&&!strcmp(dir->name,"directory"));
    unsigned count=0;
    for(vfs_node_t *file=dir->first_child;file;file=file->next_sibling) {
        unsigned id=file->disk_id-1;CHECK(file->parent==dir&&id<256);
        CHECK(file->size==(id==128?256*1024:37));
        for(size_t j=0;j<file->size;++j)CHECK((unsigned char)file->data[j]==(unsigned char)id);
        CHECK(file->data[file->size]==0);++count;
    }
    CHECK(count==256);
    alixfs_mount_destroy(fs);free_node(root);
    root=new_root("failed-read",NULL,mount);fs=alixfs_mount_create(disk);CHECK(fs);
    disk->fail_read=true;CHECK(!alixfs_mount_load(fs,mount));disk->fail_read=false;
    alixfs_mount_destroy(fs);free_node(root);free(mount);free(disk->bytes);free(disk);
}
int main(void) {
    mount_reader_edges();
    mount_read_regression();
    for(unsigned version=2;version<=4;++version)legacy_modes(version);
    block_device_t *disk=calloc(1,sizeof(*disk)); CHECK(disk);
    disk->sector_size=512; disk->sector_count=8192; disk->bytes=calloc(disk->sector_count,512); CHECK(disk->bytes);
    CHECK(alixfs_mount_format(disk));
    vfs_mount_t *outer=calloc(1,sizeof(*outer)),*mount=calloc(1,sizeof(*mount)); CHECK(outer && mount);
    vfs_node_t *parent=alixfs_new_node(VFS_NODE_DIR); CHECK(parent); parent->disk_id=1234; parent->mount=outer;
    vfs_node_t *root=new_root("first-mount",parent,mount);
    alixfs_mount_t *fs=alixfs_mount_create(disk); CHECK(fs && alixfs_mount_load(fs,mount));
    CHECK(!strcmp(root->name,"first-mount") && root->parent==parent);
    vfs_node_t *file=alixfs_new_node(VFS_NODE_FILE); CHECK(file); file->name=copy("payload");
    file->parent=root; file->mount=mount; root->first_child=file; file->data=copy("persistent payload");
    file->size=strlen(file->data); file->capacity=file->size+1; file->disk_data_dirty=true; root->disk_meta_dirty=true;
    CHECK(alixfs_mount_flush_single(fs,root,mount,false));
    CHECK(alixfs_mount_flush_single(fs,file,mount,false) && alixfs_mount_commit(fs));
    alixfs_node_disk_v4_t *record=(void *)(disk->bytes+fs->chunks[fs->header.root_id].offset);
    CHECK(!record->name_len && record->parent_id==UINT32_MAX);
    alixfs2_chunk_entry_t *entry=&fs->chunks[fs->header.root_id];
    /* Model a disk produced by the old writer, including a former mount name. */
    const char *old_name="old-mount-name";
    record->name_len=strlen(old_name); memcpy((unsigned char *)record+sizeof(*record),old_name,record->name_len);
    entry->length=sizeof(*record)+record->name_len; alixfs_mark_chunk_dirty(fs,fs->header.root_id);
    CHECK(alixfs_mount_commit(fs)); alixfs_mount_destroy(fs); free_node(root);
    root=new_root("second-mount",parent,mount); fs=alixfs_mount_create(disk);
    CHECK(fs && alixfs_mount_load(fs,mount) && !strcmp(root->name,"second-mount") && root->parent==parent);
    file=root->first_child; CHECK(file && file->parent==root && !strcmp(file->name,"payload") &&
        !strcmp(file->data,"persistent payload") && file->size==strlen("persistent payload"));
    root->disk_meta_dirty=true;
    CHECK(alixfs_mount_flush_single(fs,root,mount,false) && alixfs_mount_commit(fs));
    record=(void *)(disk->bytes+fs->chunks[fs->header.root_id].offset);
    CHECK(record->name_len==0 && record->parent_id==UINT32_MAX && fs->chunks[fs->header.root_id].length==sizeof(*record)+sizeof(alixfs_mode_disk_t));
    /* The header write succeeds and the separate mode-tail write fails.
     * Retry must retain dirty state and never overwrite unchanged file data. */
    file->permissions=0640;file->disk_meta_dirty=true;++file->dirty_seq;disk->fail_countdown=2;
    CHECK(!alixfs_mount_flush_single(fs,file,mount,false)&&file->disk_meta_dirty);
    CHECK(alixfs_mount_flush_single(fs,file,mount,false)&&alixfs_mount_commit(fs));
    alixfs_mount_destroy(fs);free_node(root);root=new_root("third-mount",parent,mount);fs=alixfs_mount_create(disk);
    CHECK(fs&&alixfs_mount_load(fs,mount));file=root->first_child;
    CHECK(file&&file->permissions==0640&&!strcmp(file->data,"persistent payload"));
    root->disk_meta_dirty=true; disk->fail_write=true;
    CHECK(!alixfs_mount_flush_single(fs,root,mount,false) && root->disk_meta_dirty);
    disk->fail_write=false; CHECK(alixfs_mount_flush_single(fs,root,mount,false) && alixfs_mount_commit(fs));
    alixfs_mount_destroy(fs); free_node(root); free_node(parent); free(outer); free(mount); free(disk->bytes); free(disk);
    puts("ALIXFS_MOUNT_ROOT_TEST: PASS root_identity=1 old_disk=1 foreign_parent=1 payload=1 write_failure=1 modes=1 partial_metadata_failure=1");
    return 0;
}
'''
    compile_and_run("alixfs-mount-root", code)
    print("AlixFS production backend: PASS versions 2/3/4, modes, metadata retry, mount identity, payloads, bounded mount I/O, parent ordering and read-ahead edges")


if __name__ == "__main__":
    main()
