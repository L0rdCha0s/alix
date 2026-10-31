#include "unistd.h"
#include "errno.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("READLINK_TEST: FAIL %s errno=%d\n", label, errno); return 1; } } while (0)

static bool target_equals(const char *path, const char *target, char *buffer, size_t capacity)
{
    memset(buffer, 0x5a, capacity);
    errno = E2BIG;
    ssize_t count = readlink(path, buffer, capacity - 1);
    size_t length = strlen(target);
    return count == (ssize_t)length && memcmp(buffer, target, length) == 0 &&
           buffer[length] == 0x5a && buffer[capacity - 1] == 0x5a && errno == E2BIG;
}

int main(void)
{
    /* The kernel worker fixture creates these symlinks. Their targets need
     * not exist: readlink returns the stored target rather than following it. */
    static const char link[] = "/tmp/vfs-owned-test/link";
    static const char target[] = "../zones/Area/City";
    char *buffer = malloc(128);
    CHECK(buffer != NULL, "heap buffer");
    CHECK(target_equals(link, target, buffer, 128), "raw bytes without NUL");
    memset(buffer, 0x5a, 128);
    CHECK(readlink(link, buffer, 5) == 5 && memcmp(buffer, target, 5) == 0 &&
          buffer[5] == 0x5a, "truncation preserves next byte");
    memset(buffer, 0x5a, 128);
    CHECK(readlink(link, buffer, strlen(target)) == (ssize_t)strlen(target) &&
          memcmp(buffer, target, strlen(target)) == 0 && buffer[strlen(target)] == 0x5a,
          "exact target capacity");
    CHECK(target_equals("/tmp/vfs-owned-test/alias", "dir", buffer, 128), "final link is not followed");
    CHECK(target_equals("/tmp/vfs-owned-test/alias/leaf", "../../zones/Area/City", buffer, 128),
          "intermediate directory symlink followed");
    errno = 0;
    CHECK(readlink("/tmp/vfs-owned-test/dir", buffer, 127) == -1 && errno == EINVAL, "directory is not a symlink");
    FILE *regular = fopen("/tmp/vfs-owned-test/readlink-regular", "w");
    CHECK(regular != NULL && fclose(regular) == 0, "create ordinary file");
    errno = 0;
    CHECK(readlink("/tmp/vfs-owned-test/readlink-regular", buffer, 127) == -1 && errno == EINVAL,
          "ordinary file is not a symlink");
    errno = 0;
    CHECK(readlink("/tmp/vfs-owned-test/absent", buffer, 127) == -1 && errno == ENOENT, "missing path");
    errno = 0;
    CHECK(readlink(link, NULL, 5) == -1 && errno == EFAULT, "bad output pointer");
    errno = 0;
    CHECK(readlink(link, buffer, 0) == -1 && errno == EINVAL, "zero capacity");
    free(buffer);
    serial_printf("READLINK_TEST: PASS bytes=1 truncation=1 intermediate=1 errors=1\n");
    return 0;
}
