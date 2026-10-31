#include "locale.h"
#include "errno.h"
#include "stdlib.h"
#include "locale_platform.h"

/* All installed category values are immutable C/POSIX data. Handles remain
 * distinct owned objects; selection is per-thread and does not call setlocale.
 * The caller must not free a handle still selected by any thread. */
struct alix_locale { struct alix_locale *next; };
static locale_t locale_registry;
static alix_mutex_t locale_registry_lock;
static _Thread_local locale_t thread_locale;

extern int __alix_locale_mask_supported(unsigned mask, const char *name);

static bool locale_registered_locked(locale_t value)
{
    for (locale_t entry = locale_registry; entry; entry = entry->next)
        if (entry == value) return true;
    return false;
}

locale_t newlocale(int mask, const char *name, locale_t base)
{
    if (!name || ((unsigned)mask & ~LC_ALL_MASK) || base == LC_GLOBAL_LOCALE)
    { errno = EINVAL; return NULL; }
    if (!__alix_locale_mask_supported((unsigned)mask, name))
    { errno = ENOENT; return NULL; }
    if (base)
    {
        alix_mutex_lock(&locale_registry_lock);
        bool valid = locale_registered_locked(base);
        alix_mutex_unlock(&locale_registry_lock);
        if (!valid) { errno = EINVAL; return NULL; }
        /* Each selected replacement is equivalent to the existing C value.
         * Return the existing valid handle; failures above preserve it. */
        return base;
    }
    locale_t value = malloc(sizeof(*value));
    if (!value) { errno = ENOMEM; return NULL; }
    alix_mutex_lock(&locale_registry_lock);
    value->next = locale_registry;
    locale_registry = value;
    alix_mutex_unlock(&locale_registry_lock);
    return value;
}

void freelocale(locale_t value)
{
    alix_mutex_lock(&locale_registry_lock);
    locale_t *slot = &locale_registry;
    while (*slot && *slot != value) slot = &(*slot)->next;
    if (!*slot)
    {
        alix_mutex_unlock(&locale_registry_lock);
        errno = EINVAL;
        return;
    }
    *slot = value->next;
    alix_mutex_unlock(&locale_registry_lock);
    free(value);
}

locale_t duplocale(locale_t value)
{
    if (value != LC_GLOBAL_LOCALE)
    {
        alix_mutex_lock(&locale_registry_lock);
        bool valid = locale_registered_locked(value);
        alix_mutex_unlock(&locale_registry_lock);
        if (!valid) { errno = EINVAL; return NULL; }
    }
    return newlocale(LC_ALL_MASK, "C", NULL);
}

locale_t uselocale(locale_t value)
{
    locale_t previous = thread_locale ? thread_locale : LC_GLOBAL_LOCALE;
    if (!value) return previous;
    if (value != LC_GLOBAL_LOCALE)
    {
        alix_mutex_lock(&locale_registry_lock);
        bool valid = locale_registered_locked(value);
        alix_mutex_unlock(&locale_registry_lock);
        if (!valid) { errno = EINVAL; return NULL; }
    }
    thread_locale = value;
    return previous;
}
