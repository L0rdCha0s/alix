#!/usr/bin/env python3
"""Exercise native locale handles, category selection and TLS ownership."""
from pathlib import Path
import argparse
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--sanitizer", choices=("address,undefined", "thread"), default="address,undefined")
args = parser.parse_args()

prefix = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
#include <locale.h>
static size_t live;
static bool fail_allocation;
static void *checked_malloc(size_t size) {
    if (fail_allocation) return NULL;
    void *value = malloc(size);
    if (value) __atomic_add_fetch(&live, 1, __ATOMIC_RELAXED);
    return value;
}
static void checked_free(void *value) {
    if (value) { __atomic_sub_fetch(&live, 1, __ATOMIC_RELAXED); free(value); }
}
typedef struct { uint32_t state; } alix_mutex_t;
static void alix_mutex_lock(alix_mutex_t *lock) {
    while (__atomic_exchange_n(&lock->state, 1, __ATOMIC_ACQUIRE)) sched_yield();
}
static void alix_mutex_unlock(alix_mutex_t *lock) { __atomic_store_n(&lock->state, 0, __ATOMIC_RELEASE); }
'''
for name in ("LC_ALL", "LC_COLLATE", "LC_CTYPE", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "LC_MESSAGES"):
    prefix += f"\n#undef {name}\n#undef {name}_MASK\n"
prefix += "\n#undef LC_GLOBAL_LOCALE\n"
for name in ("locale_t", "lconv", "setlocale", "localeconv", "newlocale", "freelocale",
             "duplocale", "uselocale", "strcoll", "strxfrm"):
    prefix += f"#define {name} alix_{name}\n"
prefix += "#define malloc checked_malloc\n#define free checked_free\n"
prefix += (ROOT / "include/locale.h").read_text() + "\n"
for file in ("locale.c", "locale_objects.c"):
    prefix += re.sub(r'^#include[^\n]*$', '', (ROOT / "user/lib" / file).read_text(), flags=re.M) + "\n"

test = r'''
static void *worker(void *unused) {
    (void)unused;
    assert(uselocale(NULL) == LC_GLOBAL_LOCALE);
    for (unsigned i=0; i<3000; ++i) {
        locale_t first = newlocale(LC_CTYPE_MASK | LC_NUMERIC_MASK, "POSIX", NULL);
        locale_t second = duplocale(first);
        assert(first && second && first != second);
        assert(uselocale(first) == LC_GLOBAL_LOCALE && uselocale(NULL) == first);
        sched_yield();
        assert(uselocale(NULL) == first);
        assert(uselocale(second) == first);
        assert(uselocale(LC_GLOBAL_LOCALE) == second);
        freelocale(first); freelocale(second);
    }
    return NULL;
}
int main(void) {
    const char *variables[] = {"LC_ALL","LC_COLLATE","LC_CTYPE","LC_MONETARY","LC_NUMERIC","LC_TIME","LC_MESSAGES","LANG"};
    for (unsigned i=0; i<sizeof(variables)/sizeof(variables[0]); ++i) unsetenv(variables[i]);
    assert(uselocale(NULL) == LC_GLOBAL_LOCALE);
    locale_t first = newlocale(LC_ALL_MASK, "C", NULL);
    assert(first && live == 1);
    assert(newlocale(LC_NUMERIC_MASK, "POSIX", first) == first && live == 1);
    assert(!newlocale(LC_TIME_MASK, "en_AU.UTF-8", first) && errno == ENOENT && live == 1);
    locale_t copy = duplocale(first);
    assert(copy && copy != first && live == 2);
    assert(uselocale(copy) == LC_GLOBAL_LOCALE);
    assert(!uselocale((locale_t)1) && errno == EINVAL && uselocale(NULL) == copy);
    assert(uselocale(first) == copy);
    assert(uselocale(LC_GLOBAL_LOCALE) == first);
    freelocale(copy);
    assert(!newlocale(-1,"C",first) && errno == EINVAL);
    assert(!newlocale(LC_ALL_MASK,NULL,first) && errno == EINVAL);
    assert(!newlocale(LC_ALL_MASK,"C",LC_GLOBAL_LOCALE) && errno == EINVAL);
    assert(!duplocale(NULL) && errno == EINVAL);
    setenv("LC_TIME","unavailable",1);
    assert(!newlocale(LC_TIME_MASK,"",NULL) && errno == ENOENT);
    copy = newlocale(LC_NUMERIC_MASK,"",NULL);
    assert(copy); freelocale(copy);
    copy = newlocale(0,"unavailable",NULL);
    assert(copy); freelocale(copy);
    setenv("LC_ALL","POSIX",1);
    copy = newlocale(LC_ALL_MASK,"",NULL);
    assert(copy); freelocale(copy);
    fail_allocation = true;
    assert(!duplocale(LC_GLOBAL_LOCALE) && errno == ENOMEM && live == 1);
    assert(newlocale(LC_TIME_MASK,"C",first) == first);
    fail_allocation = false;
    freelocale(first);
    assert(!live);
    pthread_t threads[8];
    for (unsigned i=0;i<8;++i) assert(!pthread_create(&threads[i],NULL,worker,NULL));
    for (unsigned i=0;i<8;++i) assert(!pthread_join(threads[i],NULL));
    assert(!live && !locale_registry && uselocale(NULL) == LC_GLOBAL_LOCALE);
    char buffer[8]; memset(buffer,'#',sizeof(buffer));
    assert(strxfrm(NULL,"abc",0) == 3);
    assert(strxfrm(buffer,"abc",2) == 3 && !memcmp(buffer,"ab######",8));
    assert(strxfrm(buffer,"abc",4) == 3 && !strcmp(buffer,"abc") && buffer[4]=='#');
    assert(strcoll("a","b") < 0 && strcoll("\x80","\x7f") > 0);
    puts("Native locale objects: 48000 concurrent handle lifetimes, TLS selection, categories, OOM and collation PASS");
}
'''
with tempfile.TemporaryDirectory(prefix="alix-locale-objects-") as directory:
    path = Path(directory) / "test.c"
    binary = Path(directory) / "test"
    path.write_text(prefix + test)
    subprocess.run(["cc", "-std=c11", "-D_DARWIN_C_SOURCE", "-D_POSIX_C_SOURCE=200809L",
                    "-Wall", "-Wextra", "-Werror", "-pthread", "-fsanitize=" + args.sanitizer,
                    str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
