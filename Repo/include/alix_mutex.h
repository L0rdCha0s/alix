#ifndef ALIX_MUTEX_H
#define ALIX_MUTEX_H

#include "types.h"

typedef struct
{
    volatile uint32_t state;
} alix_mutex_t;

#ifdef __cplusplus
extern "C" {
#endif
void alix_mutex_init(alix_mutex_t *mutex);
void alix_mutex_lock(alix_mutex_t *mutex);
void alix_mutex_unlock(alix_mutex_t *mutex);
bool alix_mutex_trylock(alix_mutex_t *mutex);
#ifdef __cplusplus
}
#endif

#endif
