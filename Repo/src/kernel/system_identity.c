#include "system_identity.h"
#include "heap.h"
#include "libc.h"
#include "errno.h"

extern const unsigned char __kernel_build_id_start[], __kernel_build_id_end[];
_Static_assert(sizeof(syscall_utsname_t) == 325, "native utsname ABI");

static int identity_build_version(char *version, const unsigned char *note, size_t bytes)
{
    /* GNU sha1 note: three 32-bit lengths/type, GNU plus NUL, 20 digest bytes. */
    if (bytes != 36 || note[0] != 4 || note[4] != 20 || note[8] != 3 ||
        note[1] || note[2] || note[3] || note[5] || note[6] || note[7] ||
        note[9] || note[10] || note[11] || memcmp(note + 12, "GNU\0", 4)) return -EIO;
    static const char hex[] = "0123456789abcdef";
    memcpy(version, "build:", 6);
    for (size_t index = 0; index < 20; ++index)
    {
        version[6 + 2 * index] = hex[note[16 + index] >> 4];
        version[7 + 2 * index] = hex[note[16 + index] & 15];
    }
    version[46] = 0; return 0;
}

static bool identity_space(unsigned char byte)
{ return byte == ' ' || byte == '\t' || byte == '\n' || byte == '\r'; }

static int identity_hostname(syscall_utsname_t *reply, const unsigned char *data, size_t size)
{
    if (memchr(data, 0, size)) return -EINVAL;
    size_t start = 0, end = size;
    while (start < end && identity_space(data[start])) ++start;
    while (end > start && identity_space(data[end - 1])) --end;
    if (end == start) { memcpy(reply->nodename, "alix", 5); return 0; }
    if (end - start >= sizeof(reply->nodename)) return -ENAMETOOLONG;
    memcpy(reply->nodename, data + start, end - start); reply->nodename[end - start] = 0;
    return 0;
}

int system_identity_snapshot(vfs_node_t *cwd, uint32_t uid, uint32_t gid, syscall_utsname_t *reply)
{
    if (!cwd || !reply) return -EINVAL;
    memset(reply, 0, sizeof(*reply));
    memcpy(reply->sysname, "Alix", 5); memcpy(reply->release, "development", 12);
#if defined(__x86_64__)
    memcpy(reply->machine, "x86_64", 7);
#else
#error Native machine identity must be defined for this architecture
#endif
    int error = identity_build_version(reply->version, __kernel_build_id_start,
                                         (size_t)(__kernel_build_id_end - __kernel_build_id_start));
    if (error) return error;
    vfs_node_t *node = NULL;
    error = vfs_open_data_flags_owned(cwd, "/etc/hostname", false, false, false, uid, gid, &node);
    if (error == -ENOENT) { memcpy(reply->nodename, "alix", 5); return 0; }
    if (error) return error;
    unsigned char *text = NULL; size_t size = 0;
    error = vfs_file_snapshot_owned(node, 4096, &text, &size);
    vfs_node_release_owned(node);
    if (!error) error = identity_hostname(reply, text, size);
    free(text); return error;
}
