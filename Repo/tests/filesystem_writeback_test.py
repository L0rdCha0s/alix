#!/usr/bin/env python3
"""Execute production AlixFS/VFS writeback against a counted, faultable disk."""

from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run, function_definition

ROOT = Path(__file__).resolve().parents[1]


def without_includes(path: str) -> str:
    return re.sub(r"^#include[^\n]*\n", "", (ROOT / path).read_text(), flags=re.M)


def main() -> int:
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#define CHECK(c, msg) do { if (!(c)) { fprintf(stderr, "%s\n", msg); exit(1); } } while (0)
typedef struct { unsigned locked; } spinlock_t;
typedef struct { spinlock_t lock; } wait_queue_t;
static void spinlock_init(spinlock_t *lock) { lock->locked = 0; }
static void spinlock_lock(spinlock_t *lock) { if (lock->locked++) abort(); }
static void spinlock_unlock(spinlock_t *lock) { if (!lock->locked--) abort(); }
'''
    for path in ("include/block.h", "include/vfs.h", "src/kernel/vfs_internal.h", "include/alixfs.h"):
        program += without_includes(path)
    program += r'''
static unsigned reads, writes, flushes, fail_write;
static size_t written;
static bool fail_flush;
static uint8_t *disk;
bool block_read(block_device_t *dev, uint64_t lba, uint32_t count, void *buf)
{
    if (lba + count > dev->sector_count) return false;
    reads++; memcpy(buf, disk + lba * 512u, count * 512u); return true;
}
bool block_write(block_device_t *dev, uint64_t lba, uint32_t count, const void *buf)
{
    if (lba + count > dev->sector_count) return false;
    writes++;
    if (fail_write && writes == fail_write) return false;
    written += count * 512u; memcpy(disk + lba * 512u, buf, count * 512u); return true;
}
bool block_flush(block_device_t *dev) { (void)dev; flushes++; return !fail_flush; }
'''
    program += r"""
typedef uintptr_t paddr_t;
typedef struct {bool active;} fd_description_t;
typedef struct vfs_file_mapping vfs_file_mapping_t;
static unsigned physical_live;
static int fail_physical=-1;
static bool fd_description_referenced(const fd_description_t *d) {return d->active;}
static bool user_memory_alloc_page(paddr_t *out) {
    if(fail_physical==0)return false;
    if(fail_physical>0)--fail_physical;
    void *p=malloc(4096);if(!p)return false;*out=(uintptr_t)p;++physical_live;return true;
}
static void user_memory_free_page(paddr_t p) {CHECK(physical_live,"physical page ownership");--physical_live;free((void *)p);}
static void *phys_to_virt(paddr_t p) {return (void *)p;}
static uint64_t timekeeping_now_seconds(void) {return 123456;}
"""
    vfs = (ROOT / "src/kernel/vfs.c").read_text()
    program += function_definition(vfs, "void vfs_queue_dirty_node") + "\n"
    program += without_includes("src/kernel/vfs_mapping.c")
    program += without_includes("src/kernel/alixfs.c")
    vfs = (ROOT / "src/kernel/vfs.c").read_text()
    program += "\n".join(re.findall(r"^#define VFS_[^\n]+", vfs, flags=re.M)) + "\n"
    program += r'''
static uint64_t now_ticks = 1000;
static uint64_t timer_ticks(void) { return now_ticks; }
static uint32_t timer_frequency(void) { return 1000; }
static uint64_t vfs_ticks_to_ms(uint64_t ticks) { return ticks; }
static void vfs_tree_lock_acquire(void) {}
static void vfs_tree_lock_release(void) {}
static bool vfs_sync_lock_acquire(vfs_mount_t *m) { CHECK(!m->sync_lock.locked, "nested mount lock"); m->sync_lock.locked = true; return true; }
static void vfs_sync_lock_release(vfs_mount_t *m) { CHECK(m->sync_lock.locked, "mount lock not owned"); m->sync_lock.locked = false; }
static void vfs_lock_node_data(vfs_node_t *n) { spinlock_lock(&n->data_lock); vfs_mapping_pull_locked(n); }
static void vfs_unlock_node_data(vfs_node_t *n) { spinlock_unlock(&n->data_lock); }
void vfs_node_retain(vfs_node_t *n) { n->refcount++; }
void vfs_node_release(vfs_node_t *n) { CHECK(n->refcount > 1, "lost tree reference"); n->refcount--; }
void vfs_node_release_owned(vfs_node_t *n) {vfs_node_release(n);}
static void vfs_mark_mount_dirty(vfs_mount_t *m) { m->dirty = true; m->dirty_seq++; }
static bool vfs_logs_enabled(void) { return false; }
static void serial_printf(const char *fmt, ...) { (void)fmt; }
static void vfs_log_sync_result(const char *name, const char *status, uint64_t start, size_t bytes)
{ (void)name; (void)status; (void)start; (void)bytes; }
'''
    for signature in ("static bool vfs_mount_flush_tree", "static void vfs_dequeue_clean_node", "static bool vfs_mount_flush_single", "static bool vfs_mount_collect_mapped", "static bool vfs_mount_flush_queued", "static bool vfs_mount_writeback"):
        program += function_definition(vfs, signature) + "\n"
    program += r'''
bool vfs_flush_node(vfs_node_t *n) {return vfs_mount_flush_single(n);}
static void reset_counts(void) { reads = writes = flushes = fail_write = 0; written = 0; fail_flush = false; }
static vfs_node_t *add_node(vfs_mount_t *mount, vfs_node_t *parent, const char *name, vfs_node_type_t type, size_t bytes)
{
    vfs_node_t *node = alixfs_new_node(type); CHECK(node, "node allocation");
    node->mount = mount; node->parent = parent; node->name = malloc(strlen(name) + 1);
    strcpy(node->name, name); node->size = bytes;
    if (bytes) { node->data = malloc(bytes); memset(node->data, 0x57, bytes); }
    node->disk_data_dirty = bytes != 0; node->disk_meta_dirty = true;
    node->next_sibling = parent->first_child; parent->first_child = node;
    parent->disk_meta_dirty = true; vfs_queue_dirty_node(parent); vfs_queue_dirty_node(node);
    return node;
}
static vfs_node_t *child(vfs_node_t *parent, const char *name)
{
    for (vfs_node_t *n = parent->first_child; n; n = n->next_sibling)
        if (!strcmp(n->name, name)) return n;
    return NULL;
}
static void free_tree(vfs_node_t *node)
{
    while (node->first_child) { vfs_node_t *c = node->first_child; node->first_child = c->next_sibling; free_tree(c); }
    free(node->name); free(node->data); free(node);
}
static void check_remount(block_device_t *dev, vfs_node_t *expected)
{
    alixfs_mount_t *fs = alixfs_mount_create(dev);
    vfs_node_t *root = alixfs_new_node(VFS_NODE_DIR);
    vfs_mount_t mount = {.device = dev, .mount_point = root, .backend = fs};
    CHECK(alixfs_mount_load(fs, &mount), "remount failed");
    vfs_node_t *dir = child(root, "newdir"); CHECK(dir, "new parent directory was not persisted");
    vfs_node_t *actual = child(dir, "large.bin"); CHECK(actual, "new file was not linked on remount");
    CHECK(actual->size == expected->size, "persisted length changed");
    CHECK(!memcmp(actual->data, expected->data, expected->size), "persisted file bytes changed");
    CHECK(actual->atime == expected->atime && actual->uid == expected->uid && actual->permissions == expected->permissions, "metadata update lost");
    free_tree(root); alixfs_mount_destroy(fs);
}
int main(void)
{
    block_device_t dev = {.sector_size = 512u, .sector_count = 65536u};
    disk = calloc(dev.sector_count, dev.sector_size); CHECK(disk, "disk allocation");
    CHECK(alixfs_mount_format(&dev), "format failed");
    alixfs_mount_t *fs = alixfs_mount_create(&dev);
    vfs_node_t *root = alixfs_new_node(VFS_NODE_DIR);
    vfs_mount_t mount = {.device = &dev, .mount_point = root, .backend = fs};
    CHECK(alixfs_mount_load(fs, &mount), "mount failed");
    vfs_node_t *dir = add_node(&mount, root, "newdir", VFS_NODE_DIR, 0);
    vfs_node_t *node = add_node(&mount, dir, "large.bin", VFS_NODE_FILE, 8u * 1024u * 1024u);
    reset_counts(); CHECK(vfs_mount_flush_single(node), "initial file sync failed");
    CHECK(flushes == 1, "file sync omitted hardware cache flush");
    CHECK(root->refcount == 1 && dir->refcount == 1 && node->refcount == 1, "sync leaked references");
    check_remount(&dev, node);

    reset_counts(); node->disk_meta_dirty = true; node->atime++; node->uid = 123;
    CHECK(vfs_mount_flush_single(node), "metadata-only sync failed");
    CHECK(reads == 2 && writes == 2 && written == 1024, "metadata-only prefix/mode update rewrote file data");
    CHECK(flushes == 1, "metadata sync omitted cache flush");
    check_remount(&dev, node);

    reset_counts();
    for (unsigned id = 0; id < 32; ++id) alixfs_mark_chunk_dirty(fs, id);
    CHECK(alixfs_flush_chunk_table(fs), "table commit failed");
    CHECK(reads == 0 && writes == 1 && written == 512, "adjacent table entries were not sector-batched");
    reset_counts(); alixfs_mark_chunk_dirty(fs, 31); alixfs_mark_chunk_dirty(fs, 32); fail_write = 2;
    CHECK(!alixfs_flush_chunk_table(fs), "injected second-sector failure was ignored");
    CHECK(!(fs->chunk_dirty_bitmap[31 / 8] & (1u << (31 % 8))), "successful sector remained dirty");
    CHECK(fs->chunk_dirty_bitmap[32 / 8] & (1u << (32 % 8)), "failed sector lost dirty state");
    reset_counts(); CHECK(alixfs_flush_chunk_table(fs), "table retry failed");
    CHECK(writes == 1 && reads == 0, "retry rewrote already committed sectors");

    reset_counts(); CHECK(vfs_mount_writeback(&mount, true), "forced clean sync failed");
    CHECK(writes == 0 && flushes == 1, "forced clean sync rewrote clean files");
    node->data[111] ^= 0x44; node->disk_data_dirty = true; node->dirty_seq++;
    node->pending_dirty_bytes = 1; node->last_data_write_tick = now_ticks;
    mount.dirty_bytes = 1; vfs_queue_dirty_node(node);
    reset_counts(); CHECK(vfs_mount_writeback(&mount, false), "background sync failed");
    CHECK(writes == 0 && node->disk_data_dirty && mount.dirty, "active writer grace was not retained");
    CHECK(vfs_mount_writeback(&mount, true), "forced dirty sync failed");
    CHECK(written >= node->size && !node->disk_data_dirty && flushes == 1, "forced sync deferred dirty file");
    check_remount(&dev, node);

    /* Failed growth must not free the old extent or advertise an unwritten one. */
    alixfs2_chunk_entry_t before = fs->chunks[node->disk_id];
    node->data = realloc(node->data, node->size + 4096); memset(node->data + node->size, 0x39, 4096);
    node->size += 4096; node->disk_data_dirty = true; node->dirty_seq++;
    reset_counts(); fail_write = 1;
    CHECK(!alixfs_write_node(fs, node, false), "injected payload write failure ignored");
    CHECK(!memcmp(&before, &fs->chunks[node->disk_id], sizeof(before)), "failed growth replaced old extent");
    CHECK(node->disk_data_dirty, "failed growth cleared dirty data");
    reset_counts(); CHECK(vfs_mount_flush_single(node), "growth retry failed"); check_remount(&dev, node);

    reset_counts(); node->disk_meta_dirty = true; fail_flush = true;
    CHECK(!vfs_mount_flush_single(node), "device flush failure reported success");
    CHECK(mount.dirty && !mount.needs_full_sync, "flush failure was not queued for incremental recovery");
    reset_counts(); CHECK(vfs_mount_writeback(&mount, true), "recovery sync failed");
    CHECK(!mount.needs_full_sync, "recovery state was not cleared"); check_remount(&dev, node);
    /* Production shared-page cache and writeback: independent alias identity,
     * private copies, partial allocation rollback and device error propagation. */
    fd_description_t owner={true};vfs_file_mapping_t *mapping=NULL,*alias=NULL,*copy=NULL;
    CHECK(!vfs_mapping_create(node,0,8192,true,&owner,&mapping),"shared mapping creation");
    CHECK(!vfs_mapping_create(node,4096,4096,true,&owner,&alias),"shared alias creation");
    CHECK(vfs_mapping_page(mapping,1)==vfs_mapping_page(alias,0),"aliases do not share physical page");
    CHECK(!vfs_mapping_create(node,0,4096,false,&owner,&copy),"private snapshot creation");
    unsigned char original=node->data[111];
    ((unsigned char *)phys_to_virt(vfs_mapping_page(copy,0)))[111]^=0x77;
    CHECK(!vfs_mapping_sync(copy) && node->data[111]==(char)original,"private copy reached file");
    ((unsigned char *)phys_to_virt(vfs_mapping_page(mapping,0)))[111]^=0x2a;
    reset_counts();fail_write=1;
    CHECK(vfs_mapping_sync(mapping)==-EIO && node->disk_data_dirty,"mapped write failure lost dirty state");
    reset_counts();fail_flush=true;
    CHECK(vfs_mapping_sync(mapping)==-EIO && mount.dirty && !mount.needs_full_sync,"mapped flush failure ignored");
    reset_counts();CHECK(!vfs_mapping_sync(mapping) && flushes==1,"mapped synchronous retry failed");
    CHECK(node->data[111]==(char)(original^0x2a),"shared store missing from file buffer");
    check_remount(&dev,node);
    unsigned live=physical_live;fail_physical=1;vfs_file_mapping_t *failed=NULL;
    CHECK(vfs_mapping_create(node,8192,8192,false,&owner,&failed)==-ENOMEM && !failed && physical_live==live,"private allocation rollback leaked pages");
    fail_physical=-1;
    vfs_mapping_release(alias);vfs_mapping_release(mapping);
    CHECK(mount.mapped_files==1,"private snapshot prematurely dropped shared cache");
    /* The private mapping owns no shared pages, but keeps the node registry alive. */
    vfs_mapping_release(copy);
    CHECK(!physical_live && !mount.mapped_files && node->refcount==1,"mapping retirement leaked ownership");
    free_tree(root); alixfs_mount_destroy(fs); free(disk);
    puts("filesystem writeback test passed");
    return 0;
}
'''
    compile_and_run("filesystem-writeback", program)
    print("filesystem writeback test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"filesystem writeback test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
