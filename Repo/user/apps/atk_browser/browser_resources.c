#include "browser_internal.h"

#include "string.h"

#define BROWSER_RESOURCE_SET_INIT_CAP 128u

static uint32_t browser_resource_hash(const char *url, browser_resource_kind_t kind)
{
    if (!url)
    {
        return 0;
    }
    uint32_t hash = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)url; *p; ++p)
    {
        hash ^= (uint32_t)(*p);
        hash *= 16777619u;
    }
    hash ^= (uint32_t)kind + 0x9E3779B9u + (hash << 6) + (hash >> 2);
    return hash;
}

bool browser_resource_set_init(browser_resource_set_t *set)
{
    if (!set)
    {
        return false;
    }
    memset(set, 0, sizeof(*set));
    size_t cap = (size_t)BROWSER_RESOURCE_SET_INIT_CAP;
    browser_resource_entry_t *entries = (browser_resource_entry_t *)calloc(cap, sizeof(*entries));
    if (!entries)
    {
        return false;
    }
    set->entries = entries;
    set->cap = cap;
    set->count = 0;
    return true;
}

void browser_resource_set_destroy(browser_resource_set_t *set)
{
    if (!set)
    {
        return;
    }
    if (set->entries)
    {
        for (size_t i = 0; i < set->cap; ++i)
        {
            free(set->entries[i].url);
            set->entries[i].url = NULL;
        }
        free(set->entries);
    }
    memset(set, 0, sizeof(*set));
}

static bool browser_resource_set_grow(browser_resource_set_t *set)
{
    if (!set)
    {
        return false;
    }
    size_t new_cap = set->cap ? (set->cap * 2u) : (size_t)BROWSER_RESOURCE_SET_INIT_CAP;
    if (new_cap < set->cap)
    {
        return false;
    }
    if (new_cap > (SIZE_MAX / sizeof(browser_resource_entry_t)))
    {
        return false;
    }

    browser_resource_entry_t *entries = (browser_resource_entry_t *)calloc(new_cap, sizeof(*entries));
    if (!entries)
    {
        return false;
    }

    size_t mask = new_cap - 1u;
    for (size_t i = 0; i < set->cap; ++i)
    {
        browser_resource_entry_t entry = set->entries[i];
        if (!entry.url)
        {
            continue;
        }
        size_t idx = (size_t)(entry.hash) & mask;
        while (entries[idx].url)
        {
            idx = (idx + 1u) & mask;
        }
        entries[idx] = entry;
    }

    free(set->entries);
    set->entries = entries;
    set->cap = new_cap;
    return true;
}

browser_resource_track_t browser_resource_set_track(browser_resource_set_t *set,
                                                    browser_resource_kind_t kind,
                                                    const char *url)
{
    if (!set || !url || url[0] == '\0')
    {
        return BROWSER_RESOURCE_TRACK_ERROR;
    }
    if (!set->entries)
    {
        return BROWSER_RESOURCE_TRACK_ERROR;
    }
    if ((set->count + 1u) * 10u >= set->cap * 7u)
    {
        if (!browser_resource_set_grow(set))
        {
            return BROWSER_RESOURCE_TRACK_ERROR;
        }
    }

    uint32_t hash = browser_resource_hash(url, kind);
    size_t mask = set->cap - 1u;
    size_t idx = (size_t)hash & mask;
    for (;;)
    {
        browser_resource_entry_t *entry = &set->entries[idx];
        if (!entry->url)
        {
            char *copy = browser_strdup(url);
            if (!copy)
            {
                return BROWSER_RESOURCE_TRACK_ERROR;
            }
            entry->url = copy;
            entry->hash = hash;
            entry->kind = kind;
            set->count++;
            return BROWSER_RESOURCE_TRACK_NEW;
        }
        if (entry->hash == hash && entry->kind == kind && strcmp(entry->url, url) == 0)
        {
            return BROWSER_RESOURCE_TRACK_DUP;
        }
        idx = (idx + 1u) & mask;
    }
}
