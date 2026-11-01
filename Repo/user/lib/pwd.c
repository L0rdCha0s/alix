#include "pwd.h"
#include "errno.h"
#include "fcntl.h"
#include "stdint.h"
#include "stdlib.h"
#include "string.h"
#include "sys/stat.h"
#include "unistd.h"

_Static_assert(sizeof(struct passwd) == 48, "native passwd ABI size");
_Static_assert(offsetof(struct passwd, pw_dir) == 32, "native passwd ABI directory");

/* Alix account records: login:uid:gid:display-name:home. There are no
 * password hashes or configured shells in this public database. */
#define PWD_DATABASE_LIMIT (64u * 1024u)
typedef struct {
    const char *field[5];
    size_t length[5];
    uid_t uid;
    gid_t gid;
} pwd_record_t;

static int pwd_read_text(char **text, size_t *length)
{
    *text = NULL; *length = 0;
    int fd = open("/etc/passwd", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno ? errno : EIO;
    struct stat *info = malloc(sizeof(*info));
    if (!info) { close(fd); return ENOMEM; }
    int error = 0;
    if (fstat(fd, info)) error = errno ? errno : EIO;
    else if (info->st_size > PWD_DATABASE_LIMIT) error = EFBIG;
    size_t size = error ? 0 : (size_t)info->st_size;
    free(info);
    char *bytes = error ? NULL : malloc(size + 1);
    if (!error && !bytes) error = ENOMEM;
    size_t offset = 0;
    while (!error && offset < size)
    {
        ssize_t count = read(fd, bytes + offset, size - offset);
        if (count < 0) { if (errno == EINTR) continue; error = errno ? errno : EIO; }
        else if (count == 0) break;
        else if ((size_t)count > size - offset) error = EIO;
        else offset += (size_t)count;
    }
    close(fd);
    if (error) { free(bytes); return error; }
    bytes[offset] = 0; *text = bytes; *length = offset;
    return 0;
}

static int pwd_number(const char *bytes, size_t length, uint32_t *value)
{
    if (!length) return 0;
    uint32_t number = 0;
    for (size_t index = 0; index < length; ++index)
    {
        unsigned digit = (unsigned char)bytes[index] - (unsigned)'0';
        if (digit > 9 || number > (UINT32_MAX - digit) / 10u) return 0;
        number = number * 10u + digit;
    }
    *value = number; return 1;
}

static int pwd_parse(const char *line, size_t length, pwd_record_t *record)
{
    if (!length || line[0] == '#' || memchr(line, 0, length)) return 0;
    size_t start = 0;
    for (size_t field = 0; field < 4; ++field)
    {
        const char *colon = memchr(line + start, ':', length - start);
        if (!colon) return 0;
        record->field[field] = line + start;
        record->length[field] = (size_t)(colon - line) - start;
        start = (size_t)(colon - line) + 1;
    }
    record->field[4] = line + start; record->length[4] = length - start;
    return record->length[0] &&
        pwd_number(record->field[1], record->length[1], &record->uid) &&
        pwd_number(record->field[2], record->length[2], &record->gid);
}

static char *pwd_copy_field(char **cursor, const char *source, size_t length)
{
    char *start = *cursor;
    memcpy(start, source, length); start[length] = 0;
    *cursor += length + 1; return start;
}

static int pwd_publish(const pwd_record_t *record, struct passwd *entry,
                       char *buffer, size_t capacity, struct passwd **result)
{
    size_t prefix = record->length[4] && record->field[4][0] != '/' ? 1 : 0;
    size_t needed = record->length[0] + record->length[3] + record->length[4] + prefix + 5;
    if (needed > capacity) return ERANGE;
    char *cursor = buffer;
    entry->pw_name = pwd_copy_field(&cursor, record->field[0], record->length[0]);
    entry->pw_passwd = pwd_copy_field(&cursor, "", 0);
    entry->pw_uid = record->uid; entry->pw_gid = record->gid;
    entry->pw_gecos = pwd_copy_field(&cursor, record->field[3], record->length[3]);
    entry->pw_dir = cursor;
    if (prefix) *cursor++ = '/';
    (void)pwd_copy_field(&cursor, record->field[4], record->length[4]);
    entry->pw_shell = pwd_copy_field(&cursor, "", 0);
    *result = entry; return 0;
}

static int pwd_lookup(const char *name, uid_t uid, struct passwd *entry,
                      char *buffer, size_t capacity, struct passwd **result)
{
    if (result) *result = NULL;
    if (!entry || !buffer || !result) return EINVAL;
    char *text = NULL; size_t length = 0;
    int error = pwd_read_text(&text, &length);
    if (error) return error;
    pwd_record_t *record = calloc(1, sizeof(*record));
    if (!record) { free(text); return ENOMEM; }
    size_t name_length = name ? strlen(name) : 0;
    for (size_t start = 0; start < length;)
    {
        size_t end = start;
        while (end < length && text[end] != '\n' && text[end] != '\r') ++end;
        if (pwd_parse(text + start, end - start, record) &&
            (name ? (record->length[0] == name_length && !memcmp(name, record->field[0], name_length)) : record->uid == uid))
        { error = pwd_publish(record, entry, buffer, capacity, result); break; }
        start = end;
        while (start < length && (text[start] == '\n' || text[start] == '\r')) ++start;
    }
    free(record); free(text); return error;
}

int getpwuid_r(uid_t uid, struct passwd *entry, char *buffer, size_t capacity,
               struct passwd **result)
{
    int saved = errno;
    int error = pwd_lookup(NULL, uid, entry, buffer, capacity, result);
    errno = saved; return error;
}

int getpwnam_r(const char *name, struct passwd *entry, char *buffer, size_t capacity,
               struct passwd **result)
{
    if (!name || !name[0]) { if (result) *result = NULL; return EINVAL; }
    int saved = errno;
    int error = pwd_lookup(name, 0, entry, buffer, capacity, result);
    errno = saved; return error;
}
