#ifndef ALIX_SEMAPHORE_H
#define ALIX_SEMAPHORE_H
#ifdef TTF_HOST_BUILD
#include_next <semaphore.h>
#else
#include "types.h"
#include "time.h"
#include <limits.h>

/* Process-private unnamed semaphore. State is embedded in its owning heap or
 * static object; waits retain no library stack record in another thread. */
typedef struct { uint32_t value, sequence, waiters, magic; } sem_t;
#define SEM_VALUE_MAX INT_MAX
#define SEM_FAILED ((sem_t *)-1)
#ifdef __cplusplus
extern "C" {
#endif
int sem_init(sem_t *semaphore, int shared, unsigned value);
int sem_destroy(sem_t *semaphore);
int sem_post(sem_t *semaphore);
int sem_wait(sem_t *semaphore);
int sem_trywait(sem_t *semaphore);
int sem_timedwait(sem_t *semaphore, const struct timespec *deadline);
int sem_getvalue(sem_t *semaphore, int *value);
#ifdef __cplusplus
}
#endif
#endif
#endif
