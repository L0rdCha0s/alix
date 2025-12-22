#include "userlib.h"
#include "stdio.h"
#include "sys/stat.h"
#include "serial.h"

#ifndef UNZIP_TRACE
#define UNZIP_TRACE 1
#endif

#if UNZIP_TRACE
#define UNZIP_LOG(fmt, ...) serial_printf("[unzip] " fmt "\n", ##__VA_ARGS__)
#else
#define UNZIP_LOG(...) do { } while (0)
#endif

#define ZIP_SIG_LOCAL 0x04034B50u
#define ZIP_SIG_CENTRAL 0x02014B50u
#define ZIP_SIG_EOCD 0x06054B50u

#define ZIP_LOCAL_FIXED 30u
#define ZIP_CENTRAL_FIXED 46u
#define ZIP_EOCD_FIXED 22u
#define ZIP_MAX_EOCD_SEARCH (0xFFFFu + ZIP_EOCD_FIXED)

#define ZIP_METHOD_STORE 0u
#define ZIP_METHOD_DEFLATE 8u

#define ZIP_GP_ENCRYPTED 0x0001u
#define ZIP_GP_DATA_DESC 0x0008u

#define ZIP_BITSIZE_MAX 15

typedef struct
{
    const uint8_t *data;
    size_t size;
    size_t pos;
    uint32_t bitbuf;
    int bitcount;
} bitstream_t;

typedef struct
{
    uint16_t counts[ZIP_BITSIZE_MAX + 1];
    uint16_t symbols[288];
    uint16_t first_code[ZIP_BITSIZE_MAX + 1];
    uint16_t first_symbol[ZIP_BITSIZE_MAX + 1];
} huff_table_t;

typedef struct
{
    uint16_t flags;
    uint16_t method;
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint32_t local_offset;
    uint32_t external_attr;
    char *name;
} zip_entry_t;

typedef struct
{
    char **items;
    size_t count;
    size_t capacity;
} dir_cache_t;

static dir_cache_t g_dir_cache = {0};

static bool dir_cache_contains(const dir_cache_t *cache, const char *path)
{
    if (!cache || !path)
    {
        return false;
    }
    for (size_t i = 0; i < cache->count; ++i)
    {
        if (strcmp(cache->items[i], path) == 0)
        {
            return true;
        }
    }
    return false;
}

static bool dir_cache_add(dir_cache_t *cache, const char *path)
{
    if (!cache || !path || path[0] == '\0')
    {
        return false;
    }
    if (dir_cache_contains(cache, path))
    {
        return true;
    }

    if (cache->count >= cache->capacity)
    {
        size_t new_cap = (cache->capacity == 0) ? 8 : cache->capacity * 2;
        char **new_items = (char **)realloc(cache->items, new_cap * sizeof(char *));
        if (!new_items)
        {
            return false;
        }
        cache->items = new_items;
        cache->capacity = new_cap;
    }

    size_t len = strlen(path);
    char *copy = (char *)malloc(len + 1);
    if (!copy)
    {
        return false;
    }
    memcpy(copy, path, len);
    copy[len] = '\0';
    cache->items[cache->count++] = copy;
    return true;
}

static void dir_cache_reset(dir_cache_t *cache)
{
    if (!cache)
    {
        return;
    }
    for (size_t i = 0; i < cache->count; ++i)
    {
        free(cache->items[i]);
    }
    free(cache->items);
    cache->items = NULL;
    cache->count = 0;
    cache->capacity = 0;
}

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static int open_zip_file(const char *path)
{
    if (!path)
    {
        return -1;
    }

    UNZIP_LOG("open zip path=%s", path);
    int fd = open(path, SYSCALL_OPEN_READ);
    if (fd >= 0)
    {
        return fd;
    }

    if (path[0] != '/')
    {
        char alt[256];
        const char prefix[] = "/root/";
        size_t prefix_len = sizeof(prefix) - 1;
        size_t path_len = strlen(path);
        if (prefix_len + path_len < sizeof(alt))
        {
            memcpy(alt, prefix, prefix_len);
            memcpy(alt + prefix_len, path, path_len);
            alt[prefix_len + path_len] = '\0';
            fd = open(alt, SYSCALL_OPEN_READ);
            if (fd >= 0)
            {
                printf("unzip: opened %s\n", alt);
                UNZIP_LOG("open zip fallback path=%s", alt);
                return fd;
            }
        }
    }

    return -1;
}

static bool read_file_all(int fd, uint8_t **data_out, size_t *size_out)
{
    if (!data_out || !size_out)
    {
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        return false;
    }

    if (st.st_size == 0)
    {
        *data_out = NULL;
        *size_out = 0;
        UNZIP_LOG("read file size=0");
        return true;
    }

    size_t max_size = (size_t)-1;
    if (st.st_size > (uint64_t)max_size)
    {
        return false;
    }

    size_t size = (size_t)st.st_size;
    uint8_t *data = (uint8_t *)malloc(size);
    if (!data)
    {
        return false;
    }

    UNZIP_LOG("read file bytes=%zu", size);
    size_t offset = 0;
    while (offset < size)
    {
        ssize_t got = read(fd, data + offset, size - offset);
        if (got <= 0)
        {
            free(data);
            return false;
        }
        offset += (size_t)got;
    }

    *data_out = data;
    *size_out = size;
    return true;
}

static bool find_eocd(const uint8_t *data, size_t size, size_t *offset_out)
{
    if (!data || size < ZIP_EOCD_FIXED || !offset_out)
    {
        return false;
    }

    size_t max_search = size;
    if (max_search > ZIP_MAX_EOCD_SEARCH)
    {
        max_search = ZIP_MAX_EOCD_SEARCH;
    }

    size_t start = size - ZIP_EOCD_FIXED;
    size_t end = size - max_search;

    for (size_t pos = start + 1; pos-- > end;)
    {
        if (read_le32(data + pos) == ZIP_SIG_EOCD)
        {
            *offset_out = pos;
            UNZIP_LOG("eocd offset=%zu", pos);
            return true;
        }
        if (pos == 0)
        {
            break;
        }
    }

    return false;
}

static bool shell_exec_sync(int shell_handle, const char *command)
{
    if (shell_handle < 0 || !command || command[0] == '\0')
    {
        return false;
    }

    UNZIP_LOG("shell exec cmd=%s", command);
    int started = sys_shell_exec(shell_handle, command, 0);
    if (started < 0)
    {
        UNZIP_LOG("shell exec failed start");
        return false;
    }

    char buffer[64];
    int status = 0;
    int running = 1;
    uint64_t start_ms = sys_time_millis();
    uint64_t last_log_ms = start_ms;

    while (running)
    {
        ssize_t copied = sys_shell_poll(shell_handle,
                                        buffer,
                                        sizeof(buffer),
                                        &status,
                                        &running);
        if (copied < 0)
        {
            UNZIP_LOG("shell poll failed");
            return false;
        }
        if (running && copied == 0)
        {
            uint64_t now_ms = sys_time_millis();
            if (now_ms - last_log_ms >= 1000)
            {
                UNZIP_LOG("shell exec wait cmd=%s elapsed=%llu",
                          command,
                          (unsigned long long)(now_ms - start_ms));
                last_log_ms = now_ms;
            }
            sys_sleep_ms(1);
        }
    }

    UNZIP_LOG("shell exec done status=%d", status);
    return status == 0;
}

static bool shell_mkdir(int shell_handle, const char *path)
{
    if (!path || path[0] == '\0')
    {
        return false;
    }

    size_t path_len = strlen(path);
    size_t cmd_len = sizeof("mkdir ") - 1 + path_len;
    char *cmd = (char *)malloc(cmd_len + 1);
    if (!cmd)
    {
        return false;
    }

    memcpy(cmd, "mkdir ", sizeof("mkdir ") - 1);
    memcpy(cmd + sizeof("mkdir ") - 1, path, path_len);
    cmd[cmd_len] = '\0';

    bool ok = shell_exec_sync(shell_handle, cmd);
    if (!ok)
    {
        UNZIP_LOG("mkdir failed path=%s", path);
    }
    free(cmd);
    return ok;
}

static bool ensure_directory_path(int shell_handle, const char *path)
{
    if (!path || path[0] == '\0' || strcmp(path, ".") == 0)
    {
        return true;
    }

    UNZIP_LOG("ensure dir path=%s", path);
    size_t path_len = strlen(path);
    char *partial = (char *)malloc(path_len + 2);
    if (!partial)
    {
        return false;
    }

    size_t partial_len = 0;
    const char *cursor = path;
    if (*cursor == '/')
    {
        partial[0] = '/';
        partial_len = 1;
        cursor++;
        while (*cursor == '/')
        {
            cursor++;
        }
    }

    while (*cursor)
    {
        const char *start = cursor;
        while (*cursor && *cursor != '/')
        {
            cursor++;
        }
        size_t comp_len = (size_t)(cursor - start);
        if (comp_len == 0)
        {
            while (*cursor == '/')
            {
                cursor++;
            }
            continue;
        }

        if (partial_len > 0 && partial[partial_len - 1] != '/')
        {
            partial[partial_len++] = '/';
        }

        memcpy(partial + partial_len, start, comp_len);
        partial_len += comp_len;
        partial[partial_len] = '\0';

        if (dir_cache_contains(&g_dir_cache, partial))
        {
            UNZIP_LOG("mkdir cached path=%s", partial);
        }
        else if (!shell_mkdir(shell_handle, partial))
        {
            UNZIP_LOG("ensure dir failed path=%s", partial);
            free(partial);
            return false;
        }
        else
        {
            dir_cache_add(&g_dir_cache, partial);
        }

        while (*cursor == '/')
        {
            cursor++;
        }
    }

    free(partial);
    return true;
}

static char *path_parent(const char *path)
{
    if (!path || path[0] == '\0')
    {
        return NULL;
    }

    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/')
    {
        len--;
    }

    size_t pos = len;
    while (pos > 0 && path[pos - 1] != '/')
    {
        pos--;
    }

    if (pos == 0)
    {
        return NULL;
    }

    size_t parent_len = pos;
    if (parent_len > 1 && path[parent_len - 1] == '/')
    {
        parent_len--;
    }

    char *parent = (char *)malloc(parent_len + 1);
    if (!parent)
    {
        return NULL;
    }

    memcpy(parent, path, parent_len);
    parent[parent_len] = '\0';
    return parent;
}

static bool ensure_parent_dir(int shell_handle, const char *path)
{
    char *parent = path_parent(path);
    if (!parent)
    {
        return true;
    }

    UNZIP_LOG("ensure parent path=%s parent=%s", path, parent);
    bool ok = ensure_directory_path(shell_handle, parent);
    free(parent);
    return ok;
}

static bool write_full(int fd, const uint8_t *data, size_t len)
{
    size_t offset = 0;
    while (offset < len)
    {
        ssize_t wrote = write(fd, data + offset, len - offset);
        if (wrote <= 0)
        {
            return false;
        }
        offset += (size_t)wrote;
    }
    return true;
}

static char *zip_copy_name(const uint8_t *name, size_t len)
{
    char *out = (char *)malloc(len + 1);
    if (!out)
    {
        return NULL;
    }
    for (size_t i = 0; i < len; ++i)
    {
        char c = (char)name[i];
        if (c == '\\')
        {
            c = '/';
        }
        out[i] = c;
    }
    out[len] = '\0';
    return out;
}

static bool zip_name_safe(const char *name)
{
    if (!name || name[0] == '\0')
    {
        return false;
    }
    if (name[0] == '/')
    {
        return false;
    }

    const char *cursor = name;
    while (*cursor)
    {
        while (*cursor == '/')
        {
            cursor++;
        }
        if (*cursor == '\0')
        {
            break;
        }

        const char *start = cursor;
        while (*cursor && *cursor != '/')
        {
            cursor++;
        }
        size_t len = (size_t)(cursor - start);

        if (len == 1 && start[0] == '.')
        {
            continue;
        }
        if (len == 2 && start[0] == '.' && start[1] == '.')
        {
            return false;
        }
    }

    return true;
}

static char *path_join(const char *base, const char *name)
{
    if (!base || base[0] == '\0' || strcmp(base, ".") == 0)
    {
        size_t name_len = strlen(name);
        char *out = (char *)malloc(name_len + 1);
        if (!out)
        {
            return NULL;
        }
        memcpy(out, name, name_len);
        out[name_len] = '\0';
        return out;
    }

    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    bool need_sep = (base_len > 0 && base[base_len - 1] != '/');

    size_t total = base_len + name_len + (need_sep ? 1 : 0);
    char *out = (char *)malloc(total + 1);
    if (!out)
    {
        return NULL;
    }

    memcpy(out, base, base_len);
    size_t pos = base_len;
    if (need_sep)
    {
        out[pos++] = '/';
    }
    memcpy(out + pos, name, name_len);
    out[total] = '\0';
    return out;
}

static bool br_fill(bitstream_t *br, int count)
{
    while (br->bitcount < count)
    {
        if (br->pos >= br->size)
        {
            return false;
        }
        br->bitbuf |= (uint32_t)br->data[br->pos++] << br->bitcount;
        br->bitcount += 8;
    }
    return true;
}

static bool br_read(bitstream_t *br, int count, uint32_t *out_bits)
{
    if (count == 0)
    {
        *out_bits = 0;
        return true;
    }
    if (count > 24)
    {
        return false;
    }
    if (!br_fill(br, count))
    {
        return false;
    }
    uint32_t mask = (1u << count) - 1u;
    *out_bits = br->bitbuf & mask;
    br->bitbuf >>= count;
    br->bitcount -= count;
    return true;
}

static void br_align_byte(bitstream_t *br)
{
    br->bitbuf = 0;
    br->bitcount = 0;
}

static bool huff_build(huff_table_t *table, const uint8_t *lengths, int length_count)
{
    if (!table || !lengths || length_count <= 0)
    {
        return false;
    }

    memset(table, 0, sizeof(*table));
    for (int i = 0; i < length_count; ++i)
    {
        uint8_t len = lengths[i];
        if (len > ZIP_BITSIZE_MAX)
        {
            return false;
        }
        if (len)
        {
            table->counts[len]++;
        }
    }

    int left = 1;
    for (int len = 1; len <= ZIP_BITSIZE_MAX; ++len)
    {
        left <<= 1;
        left -= table->counts[len];
        if (left < 0)
        {
            return false;
        }
    }

    uint16_t offsets[ZIP_BITSIZE_MAX + 1];
    offsets[1] = 0;
    for (int len = 1; len < ZIP_BITSIZE_MAX; ++len)
    {
        offsets[len + 1] = offsets[len] + table->counts[len];
    }

    for (int sym = 0; sym < length_count; ++sym)
    {
        uint8_t len = lengths[sym];
        if (len == 0)
        {
            continue;
        }
        table->symbols[offsets[len]++] = (uint16_t)sym;
    }

    uint16_t code = 0;
    table->first_symbol[0] = 0;
    table->first_code[0] = 0;
    for (int bits = 1; bits <= ZIP_BITSIZE_MAX; ++bits)
    {
        code = (uint16_t)((code + table->counts[bits - 1]) << 1);
        table->first_code[bits] = code;
        table->first_symbol[bits] = (uint16_t)(table->first_symbol[bits - 1] + table->counts[bits - 1]);
    }
    return true;
}

static inline uint32_t reverse_bits(uint32_t v, int bits)
{
    uint32_t r = 0;
    for (int i = 0; i < bits; ++i)
    {
        r = (r << 1) | (v & 1u);
        v >>= 1;
    }
    return r;
}

static bool huff_decode(bitstream_t *br, const huff_table_t *table, int *out_symbol)
{
    if (!br || !table || !out_symbol)
    {
        return false;
    }

    uint32_t code = 0;

    for (int len = 1; len <= ZIP_BITSIZE_MAX; ++len)
    {
        uint32_t bit;
        if (!br_read(br, 1, &bit))
        {
            return false;
        }
        code |= bit << (len - 1);
        uint32_t count = table->counts[len];
        if (count != 0)
        {
            uint32_t rev = reverse_bits(code, len);
            uint32_t first_code = table->first_code[len];
            if (rev >= first_code && rev < first_code + count)
            {
                uint32_t idx = table->first_symbol[len] + (rev - first_code);
                if (idx < sizeof(table->symbols) / sizeof(table->symbols[0]))
                {
                    *out_symbol = table->symbols[idx];
                    return true;
                }
                return false;
            }
        }
    }
    return false;
}

static bool build_fixed_tables(huff_table_t *litlen, huff_table_t *dist)
{
    static bool built = false;
    static huff_table_t fixed_litlen;
    static huff_table_t fixed_dist;

    if (built)
    {
        if (litlen)
        {
            *litlen = fixed_litlen;
        }
        if (dist)
        {
            *dist = fixed_dist;
        }
        return true;
    }

    uint8_t *lens = (uint8_t *)malloc(288);
    uint8_t *dist_lens = (uint8_t *)malloc(32);
    if (!lens || !dist_lens)
    {
        free(lens);
        free(dist_lens);
        return false;
    }

    for (int i = 0; i <= 143; ++i) lens[i] = 8;
    for (int i = 144; i <= 255; ++i) lens[i] = 9;
    for (int i = 256; i <= 279; ++i) lens[i] = 7;
    for (int i = 280; i <= 287; ++i) lens[i] = 8;
    if (!huff_build(&fixed_litlen, lens, 288))
    {
        free(lens);
        free(dist_lens);
        return false;
    }

    for (int i = 0; i < 32; ++i) dist_lens[i] = 5;
    if (!huff_build(&fixed_dist, dist_lens, 32))
    {
        free(lens);
        free(dist_lens);
        return false;
    }

    free(lens);
    free(dist_lens);
    built = true;
    if (litlen)
    {
        *litlen = fixed_litlen;
    }
    if (dist)
    {
        *dist = fixed_dist;
    }
    return true;
}

static bool parse_dynamic_trees(bitstream_t *br, huff_table_t *litlen, huff_table_t *dist, const char **err_out)
{
#define ZIP_TREE_ERR(msg) do { if (err_out) *(err_out) = (msg); goto cleanup; } while (0)
    static const int code_order[19] = {
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
        11, 4, 12, 3, 13, 2, 14, 1, 15
    };

    bool ok = false;
    uint8_t *code_lengths = (uint8_t *)calloc(19, 1);
    uint8_t *lengths = (uint8_t *)calloc(288 + 32, 1);
    uint8_t *lit_lens = (uint8_t *)calloc(288, 1);
    uint8_t *dist_lens = (uint8_t *)calloc(32, 1);

    if (!code_lengths || !lengths || !lit_lens || !dist_lens)
    {
        ZIP_TREE_ERR("out of memory");
    }

    uint32_t hlit, hdist, hclen;
    if (!br_read(br, 5, &hlit) || !br_read(br, 5, &hdist) || !br_read(br, 4, &hclen))
    {
        ZIP_TREE_ERR("dynamic header bits exhausted");
    }
    int litlen_count = (int)(hlit + 257);
    int dist_count = (int)(hdist + 1);
    int code_count = (int)(hclen + 4);

    for (int i = 0; i < code_count; ++i)
    {
        uint32_t v = 0;
        if (!br_read(br, 3, &v))
        {
            ZIP_TREE_ERR("code length header exhausted");
        }
        code_lengths[code_order[i]] = (uint8_t)v;
    }

    huff_table_t code_table;
    if (!huff_build(&code_table, code_lengths, 19))
    {
        ZIP_TREE_ERR("code length table build failed");
    }

    int idx = 0;
    while (idx < litlen_count + dist_count)
    {
        int sym = 0;
        if (!huff_decode(br, &code_table, &sym))
        {
            ZIP_TREE_ERR("code length decode failed");
        }

        if (sym <= 15)
        {
            lengths[idx++] = (uint8_t)sym;
            continue;
        }

        uint32_t repeat = 0;
        uint8_t value = 0;
        if (sym == 16)
        {
            if (idx == 0)
            {
                ZIP_TREE_ERR("repeat before length");
            }
            value = lengths[idx - 1];
            if (!br_read(br, 2, &repeat))
            {
                ZIP_TREE_ERR("repeat length exhausted");
            }
            repeat += 3;
        }
        else if (sym == 17)
        {
            value = 0;
            if (!br_read(br, 3, &repeat))
            {
                ZIP_TREE_ERR("repeat length exhausted");
            }
            repeat += 3;
        }
        else if (sym == 18)
        {
            value = 0;
            if (!br_read(br, 7, &repeat))
            {
                ZIP_TREE_ERR("repeat length exhausted");
            }
            repeat += 11;
        }
        else
        {
            ZIP_TREE_ERR("invalid code length symbol");
        }

        if (idx + (int)repeat > litlen_count + dist_count)
        {
            ZIP_TREE_ERR("repeat overruns table");
        }
        for (uint32_t r = 0; r < repeat; ++r)
        {
            lengths[idx++] = value;
        }
    }

    for (int i = 0; i < litlen_count; ++i)
    {
        lit_lens[i] = lengths[i];
    }
    for (int i = 0; i < dist_count; ++i)
    {
        dist_lens[i] = lengths[litlen_count + i];
    }

    if (lit_lens[256] == 0)
    {
        ZIP_TREE_ERR("missing end-of-block");
    }
    if (!huff_build(litlen, lit_lens, 288))
    {
        ZIP_TREE_ERR("lit/len table build failed");
    }

    bool any_dist = false;
    for (int i = 0; i < dist_count; ++i)
    {
        if (dist_lens[i] != 0)
        {
            any_dist = true;
            break;
        }
    }
    if (!any_dist)
    {
        dist_lens[0] = 1;
    }
    if (!huff_build(dist, dist_lens, 32))
    {
        ZIP_TREE_ERR("distance table build failed");
    }

    ok = true;

cleanup:
    free(code_lengths);
    free(lengths);
    free(lit_lens);
    free(dist_lens);
    return ok;
#undef ZIP_TREE_ERR
}

static bool deflate_inflate(const uint8_t *data,
                            size_t size,
                            uint8_t *out,
                            size_t out_capacity,
                            size_t *out_size,
                            const char **err_out)
{
#define ZIP_ERR(msg) do { if (err_out) *(err_out) = (msg); return false; } while (0)
    if (!data || size == 0 || !out || !out_size)
    {
        ZIP_ERR("invalid deflate input");
    }

    bitstream_t br = {
        .data = data,
        .size = size,
        .pos = 0,
        .bitbuf = 0,
        .bitcount = 0
    };

    size_t written = 0;
    bool last_block = false;

    static const uint16_t length_base[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13,
        15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
        67, 83, 99, 115, 131, 163, 195, 227, 258
    };
    static const uint8_t length_extra[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1,
        1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
        4, 4, 4, 4, 5, 5, 5, 5, 0
    };
    static const uint16_t dist_base[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25,
        33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
        1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
    };
    static const uint8_t dist_extra[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3,
        4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
        9, 9, 10, 10, 11, 11, 12, 12, 13, 13
    };

    huff_table_t litlen = {0};
    huff_table_t dist = {0};

    while (!last_block)
    {
        uint32_t bfinal = 0, btype = 0;
        if (!br_read(&br, 1, &bfinal) || !br_read(&br, 2, &btype))
        {
            ZIP_ERR("header bits exhausted");
        }
        last_block = (bfinal != 0);

        if (btype == 0)
        {
            br_align_byte(&br);
            uint32_t len = 0, nlen = 0;
            if (!br_read(&br, 16, &len) || !br_read(&br, 16, &nlen))
            {
                ZIP_ERR("stored length read failed");
            }
            if ((len ^ 0xFFFFu) != nlen)
            {
                ZIP_ERR("stored length mismatch");
            }
            if (br.pos + len > br.size)
            {
                ZIP_ERR("stored block overruns input");
            }
            if (written + len > out_capacity)
            {
                ZIP_ERR("stored block overruns output");
            }
            memcpy(out + written, br.data + br.pos, len);
            br.pos += len;
            written += len;
            continue;
        }

        if (btype == 1)
        {
            if (!build_fixed_tables(&litlen, &dist))
            {
                ZIP_ERR("fixed tables build failed");
            }
        }
        else if (btype == 2)
        {
            if (!parse_dynamic_trees(&br, &litlen, &dist, err_out))
            {
                ZIP_ERR(*err_out ? *err_out : "dynamic tables parse failed");
            }
        }
        else
        {
            ZIP_ERR("unsupported BTYPE");
        }

        while (true)
        {
            int sym = 0;
            if (!huff_decode(&br, &litlen, &sym))
            {
                ZIP_ERR("litlen decode failed");
            }

            if (sym < 256)
            {
                if (written >= out_capacity)
                {
                    ZIP_ERR("output overflow");
                }
                out[written++] = (uint8_t)sym;
                continue;
            }
            if (sym == 256)
            {
                break;
            }

            int len_idx = sym - 257;
            if (len_idx < 0 || len_idx >= 29)
            {
                ZIP_ERR("length symbol out of range");
            }
            uint32_t length = length_base[len_idx];
            uint32_t extra_bits = length_extra[len_idx];
            if (extra_bits)
            {
                uint32_t extra_val = 0;
                if (!br_read(&br, (int)extra_bits, &extra_val))
                {
                    ZIP_ERR("length extra bits exhausted");
                }
                length += extra_val;
            }

            int dist_sym = 0;
            if (!huff_decode(&br, &dist, &dist_sym))
            {
                ZIP_ERR("distance decode failed");
            }
            if (dist_sym < 0 || dist_sym >= 30)
            {
                ZIP_ERR("distance symbol out of range");
            }
            uint32_t distance = dist_base[dist_sym];
            uint8_t dist_bits = dist_extra[dist_sym];
            if (dist_bits)
            {
                uint32_t extra_val = 0;
                if (!br_read(&br, dist_bits, &extra_val))
                {
                    ZIP_ERR("distance extra bits exhausted");
                }
                distance += extra_val;
            }

            if (distance == 0 || distance > written)
            {
                ZIP_ERR("invalid distance");
            }
            if (written + length > out_capacity)
            {
                ZIP_ERR("match overruns output");
            }
            for (uint32_t i = 0; i < length; ++i)
            {
                out[written] = out[written - distance];
                ++written;
            }
        }
    }

    *out_size = written;
    return true;
#undef ZIP_ERR
}

static bool zip_extract_entry(const uint8_t *zip_data,
                              size_t zip_size,
                              int shell_handle,
                              const char *out_dir,
                              zip_entry_t *entry)
{
    if (!zip_data || !entry || !entry->name)
    {
        return false;
    }

    UNZIP_LOG("entry name=%s method=%u flags=0x%04X comp=%u uncomp=%u offset=0x%08X",
              entry->name,
              (unsigned)entry->method,
              (unsigned)entry->flags,
              (unsigned)entry->comp_size,
              (unsigned)entry->uncomp_size,
              (unsigned)entry->local_offset);

    if (entry->flags & ZIP_GP_ENCRYPTED)
    {
        printf("unzip: skipping encrypted %s\n", entry->name);
        return true;
    }

    if (entry->method != ZIP_METHOD_STORE && entry->method != ZIP_METHOD_DEFLATE)
    {
        printf("unzip: skipping %s (method %u)\n", entry->name, (unsigned)entry->method);
        return true;
    }

    if (entry->comp_size == 0xFFFFFFFFu || entry->uncomp_size == 0xFFFFFFFFu ||
        entry->local_offset == 0xFFFFFFFFu)
    {
        printf("unzip: skipping zip64 entry %s\n", entry->name);
        return true;
    }

    if (!zip_name_safe(entry->name))
    {
        printf("unzip: unsafe path %s\n", entry->name);
        return true;
    }

    bool is_dir = false;
    size_t name_len = strlen(entry->name);
    if ((entry->external_attr & 0x10u) != 0u)
    {
        is_dir = true;
    }
    if (name_len > 0 && entry->name[name_len - 1] == '/')
    {
        is_dir = true;
    }

    char *out_path = path_join(out_dir, entry->name);
    if (!out_path)
    {
        printf("unzip: out of memory for path\n");
        return false;
    }

    UNZIP_LOG("extract path=%s", out_path);
    if (is_dir)
    {
        bool ok = ensure_directory_path(shell_handle, out_path);
        free(out_path);
        if (!ok)
        {
            printf("unzip: mkdir failed for %s\n", entry->name);
        }
        return ok;
    }

    if (!ensure_parent_dir(shell_handle, out_path))
    {
        printf("unzip: mkdir failed for %s\n", out_path);
        free(out_path);
        return false;
    }

    if (entry->local_offset + ZIP_LOCAL_FIXED > zip_size)
    {
        printf("unzip: bad local header for %s\n", entry->name);
        free(out_path);
        return false;
    }

    const uint8_t *local = zip_data + entry->local_offset;
    if (read_le32(local) != ZIP_SIG_LOCAL)
    {
        printf("unzip: invalid local signature for %s\n", entry->name);
        free(out_path);
        return false;
    }

    uint16_t local_name_len = read_le16(local + 26);
    uint16_t local_extra_len = read_le16(local + 28);
    size_t data_offset = entry->local_offset + ZIP_LOCAL_FIXED + local_name_len + local_extra_len;

    UNZIP_LOG("local header name_len=%u extra_len=%u data_offset=%zu",
              (unsigned)local_name_len,
              (unsigned)local_extra_len,
              data_offset);

    if (data_offset > zip_size || entry->comp_size > zip_size - data_offset)
    {
        printf("unzip: data overrun for %s\n", entry->name);
        free(out_path);
        return false;
    }

    int fd = open(out_path, SYSCALL_OPEN_WRITE | SYSCALL_OPEN_CREATE | SYSCALL_OPEN_TRUNCATE);
    if (fd < 0)
    {
        printf("unzip: unable to create %s\n", out_path);
        free(out_path);
        return false;
    }

    bool ok = true;
    if (entry->method == ZIP_METHOD_STORE)
    {
        const uint8_t *payload = zip_data + data_offset;
        if (entry->comp_size > 0 && !write_full(fd, payload, entry->comp_size))
        {
            printf("unzip: write failed for %s\n", out_path);
            ok = false;
        }
    }
    else
    {
        size_t alloc_size = entry->uncomp_size > 0 ? entry->uncomp_size : 1;
        uint8_t *out_buf = (uint8_t *)malloc(alloc_size);
        if (!out_buf)
        {
            printf("unzip: out of memory for %s\n", out_path);
            ok = false;
        }
        else
        {
            UNZIP_LOG("inflate start path=%s comp=%u out=%u",
                      out_path,
                      (unsigned)entry->comp_size,
                      (unsigned)entry->uncomp_size);
            size_t out_size = 0;
            const char *err = NULL;
            const uint8_t *payload = zip_data + data_offset;
            if (!deflate_inflate(payload, entry->comp_size, out_buf, alloc_size, &out_size, &err))
            {
                printf("unzip: inflate failed for %s (%s)\n", out_path, err ? err : "error");
                ok = false;
            }
            else if (out_size != (size_t)entry->uncomp_size)
            {
                printf("unzip: size mismatch for %s\n", out_path);
                ok = false;
            }
            else if (entry->uncomp_size > 0 && !write_full(fd, out_buf, entry->uncomp_size))
            {
                printf("unzip: write failed for %s\n", out_path);
                ok = false;
            }
            UNZIP_LOG("inflate done path=%s out_size=%zu ok=%d", out_path, out_size, ok ? 1 : 0);
            free(out_buf);
        }
    }

    close(fd);
    if (ok)
    {
        printf("unzip: %s\n", out_path);
    }
    free(out_path);
    return ok;
}

static void usage(void)
{
    printf("usage: unzip <zip-file> [output-dir]\n");
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage();
        return 1;
    }

    const char *zip_path = argv[1];
    const char *out_dir = (argc >= 3) ? argv[2] : ".";
    UNZIP_LOG("start zip=%s out=%s", zip_path, out_dir);

    int shell_handle = sys_shell_open();
    if (shell_handle < 0)
    {
        printf("unzip: unable to open shell session\n");
        return 1;
    }
    UNZIP_LOG("shell handle=%d", shell_handle);

    if (!ensure_directory_path(shell_handle, out_dir))
    {
        printf("unzip: unable to prepare output directory %s\n", out_dir);
        sys_shell_close(shell_handle);
        return 1;
    }

    int fd = open_zip_file(zip_path);
    if (fd < 0)
    {
        printf("unzip: unable to open %s\n", zip_path);
        sys_shell_close(shell_handle);
        return 1;
    }
    UNZIP_LOG("zip fd=%d", fd);

    uint8_t *zip_data = NULL;
    size_t zip_size = 0;
    if (!read_file_all(fd, &zip_data, &zip_size))
    {
        printf("unzip: failed to read %s\n", zip_path);
        close(fd);
        sys_shell_close(shell_handle);
        return 1;
    }
    close(fd);

    UNZIP_LOG("zip bytes=%zu", zip_size);
    if (zip_size < ZIP_EOCD_FIXED)
    {
        printf("unzip: invalid zip file\n");
        free(zip_data);
        sys_shell_close(shell_handle);
        return 1;
    }

    size_t eocd_offset = 0;
    if (!find_eocd(zip_data, zip_size, &eocd_offset))
    {
        printf("unzip: missing end of central directory\n");
        free(zip_data);
        sys_shell_close(shell_handle);
        return 1;
    }

    const uint8_t *eocd = zip_data + eocd_offset;
    if (eocd_offset + ZIP_EOCD_FIXED > zip_size)
    {
        printf("unzip: truncated end of central directory\n");
        free(zip_data);
        sys_shell_close(shell_handle);
        return 1;
    }

    uint16_t disk = read_le16(eocd + 4);
    uint16_t cd_disk = read_le16(eocd + 6);
    uint16_t entries_disk = read_le16(eocd + 8);
    uint16_t entries_total = read_le16(eocd + 10);
    uint32_t cd_size = read_le32(eocd + 12);
    uint32_t cd_offset = read_le32(eocd + 16);
    uint16_t comment_len = read_le16(eocd + 20);

    UNZIP_LOG("eocd entries=%u cd_size=%u cd_offset=%u comment_len=%u",
              (unsigned)entries_total,
              (unsigned)cd_size,
              (unsigned)cd_offset,
              (unsigned)comment_len);

    if (disk != 0 || cd_disk != 0 || entries_disk != entries_total)
    {
        printf("unzip: multi-disk zips unsupported\n");
        free(zip_data);
        sys_shell_close(shell_handle);
        return 1;
    }

    if (comment_len > 0 && eocd_offset + ZIP_EOCD_FIXED + comment_len > zip_size)
    {
        printf("unzip: invalid comment length\n");
        free(zip_data);
        sys_shell_close(shell_handle);
        return 1;
    }

    if (cd_offset == 0xFFFFFFFFu || cd_size == 0xFFFFFFFFu || entries_total == 0xFFFFu)
    {
        printf("unzip: zip64 archives unsupported\n");
        free(zip_data);
        sys_shell_close(shell_handle);
        return 1;
    }

    if ((size_t)cd_offset + (size_t)cd_size > zip_size)
    {
        printf("unzip: central directory out of range\n");
        free(zip_data);
        sys_shell_close(shell_handle);
        return 1;
    }

    size_t cursor = cd_offset;
    int failures = 0;

    for (uint16_t i = 0; i < entries_total; ++i)
    {
        if (cursor + ZIP_CENTRAL_FIXED > zip_size)
        {
            printf("unzip: central directory truncated\n");
            failures++;
            break;
        }

        if (read_le32(zip_data + cursor) != ZIP_SIG_CENTRAL)
        {
            printf("unzip: invalid central directory signature\n");
            failures++;
            break;
        }

        uint16_t flags = read_le16(zip_data + cursor + 8);
        uint16_t method = read_le16(zip_data + cursor + 10);
        uint32_t comp_size = read_le32(zip_data + cursor + 20);
        uint32_t uncomp_size = read_le32(zip_data + cursor + 24);
        uint16_t name_len = read_le16(zip_data + cursor + 28);
        uint16_t extra_len = read_le16(zip_data + cursor + 30);
        uint16_t comment_len_cd = read_le16(zip_data + cursor + 32);
        uint32_t external_attr = read_le32(zip_data + cursor + 38);
        uint32_t local_offset = read_le32(zip_data + cursor + 42);

        size_t name_offset = cursor + ZIP_CENTRAL_FIXED;
        size_t extra_offset = name_offset + name_len;
        size_t comment_offset = extra_offset + extra_len;
        size_t next = comment_offset + comment_len_cd;

        if (next > zip_size)
        {
            printf("unzip: central directory entry overrun\n");
            failures++;
            break;
        }

        char *name = NULL;
        if (name_len > 0)
        {
            name = zip_copy_name(zip_data + name_offset, name_len);
        }

        if (!name)
        {
            printf("unzip: invalid entry name\n");
            failures++;
            cursor = next;
            continue;
        }

        UNZIP_LOG("central idx=%u name_len=%u extra_len=%u comment_len=%u next=%zu",
                  (unsigned)i,
                  (unsigned)name_len,
                  (unsigned)extra_len,
                  (unsigned)comment_len_cd,
                  next);

        zip_entry_t entry = {
            .flags = flags,
            .method = method,
            .comp_size = comp_size,
            .uncomp_size = uncomp_size,
            .local_offset = local_offset,
            .external_attr = external_attr,
            .name = name
        };

        bool ok = zip_extract_entry(zip_data, zip_size, shell_handle, out_dir, &entry);
        if (!ok)
        {
            failures++;
        }

        free(name);
        cursor = next;
    }

    free(zip_data);
    sys_shell_close(shell_handle);
    dir_cache_reset(&g_dir_cache);

    if (failures != 0)
    {
        printf("unzip: completed with %d error(s)\n", failures);
        return 1;
    }

    printf("unzip: done\n");
    return 0;
}
