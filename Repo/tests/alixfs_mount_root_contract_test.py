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
    uint32_t disk_id,uid,gid,refcount; uint64_t atime,mtime,ctime,dirty_seq;
};
typedef struct { size_t sector_size; uint64_t sector_count; unsigned char *bytes; bool fail_write; } block_device_t;
static bool block_read(block_device_t *d,uint64_t lba,uint32_t count,void *out) {
    CHECK(lba <= d->sector_count && count <= d->sector_count-lba);
    memcpy(out,d->bytes+lba*d->sector_size,(size_t)count*d->sector_size); return true;
}
static bool block_write(block_device_t *d,uint64_t lba,uint32_t count,const void *in) {
    CHECK(lba <= d->sector_count && count <= d->sector_count-lba);
    if(d->fail_write) return false;
    memcpy(d->bytes+lba*d->sector_size,in,(size_t)count*d->sector_size); return true;
}
typedef struct alixfs_mount alixfs_mount_t;
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
int main(void) {
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
    CHECK(record->name_len==0 && record->parent_id==UINT32_MAX && fs->chunks[fs->header.root_id].length==sizeof(*record));
    root->disk_meta_dirty=true; disk->fail_write=true;
    CHECK(!alixfs_mount_flush_single(fs,root,mount,false) && root->disk_meta_dirty);
    disk->fail_write=false; CHECK(alixfs_mount_flush_single(fs,root,mount,false) && alixfs_mount_commit(fs));
    alixfs_mount_destroy(fs); free_node(root); free_node(parent); free(outer); free(mount); free(disk->bytes); free(disk);
    puts("ALIXFS_MOUNT_ROOT_TEST: PASS root_identity=1 old_disk=1 foreign_parent=1 payload=1 write_failure=1");
    return 0;
}
'''
    compile_and_run("alixfs-mount-root", code)
    print("AlixFS production backend: PASS portable mount name, old disk readback, foreign-parent isolation and write-failure retry")


if __name__ == "__main__":
    main()
